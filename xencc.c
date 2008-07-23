#include <linux/module.h>
#include <linux/miscdevice.h>
#include <linux/uaccess.h>
#include <linux/mm.h>

/*
XenCC v0.1 (07/2008)

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


#define DEV_NAME "xencc"

MODULE_LICENSE("GPL");
MODULE_AUTHOR ("Mickaël Salaün");
MODULE_DESCRIPTION ("Create /dev/" DEV_NAME " to communicate with an other guest through a Xen covert channel.");


// comment this for the second guest !
#define XENCC_ME_FIRST

// better with @ > PAGE_SHIFT bits (but not tactful)
#define XENCC_TAGS_1 {123456, 13641, 1616}
#define XENCC_TAGS_2 {151651, 1416, 469564}
// same dom (test):
//#define XENCC_TAGS_2 XENCC_TAGS_1

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

#define XENCC_DATA_SIZE 256

#define XENCC_VALINIT 0

#define MFN_START 0
#define MFN_END 0x00400000 // 4Mo = 2^22

//#define MSG_TYPE_HEXA

#if defined(__i386__)
#define ADDR_LENGTH sizeof(unsigned long)
#else
#error "Unsupported architecture"
#endif

static unsigned char xencc_data[XENCC_DATA_SIZE] = "";
static unsigned int xencc_data_size;

static struct page *xencc_pages;
static int xencc_pages_nb;

static void *mfn_old;
static int mfn_old_size;

// other's tags
static unsigned long pfn_oth_header_tag[] = XENCC_TAGS_A;
#define PFN_OTH_HEADER_TAG_SIZE (sizeof(pfn_oth_header_tag) / ADDR_LENGTH)

// our's tags
static unsigned long pfn_my_header_tag[] = XENCC_TAGS_B;
#define PFN_MY_HEADER_TAG_SIZE (sizeof(pfn_my_header_tag) / ADDR_LENGTH)
#define PFN_MY_HEADER_SIZE (1 + sizeof(pfn_my_header_tag) / ADDR_LENGTH)

#define DBG(...) printk(KERN_DEBUG DEV_NAME " " __VA_ARGS__);


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

static void *allocate_mfn(unsigned int nb_pages)
{
    int order;
    void *pt;
    
    for(order = 0; nb_pages > 0; order++)
        nb_pages >>= 1;
    DBG("order: %d\n", order);
    
    pt = (void *)alloc_pages(GFP_KERNEL | __GFP_REPEAT | __GFP_ZERO, order);
    xencc_pages = (struct page *)pt;
    xencc_pages_nb = order;
    DBG("alloc_pages: %p\n", pt);
    
    pt = (void *)page_to_pfn((struct page *)pt);
    if(pt == NULL) // ?
    {
        printk(KERN_ALERT DEV_NAME " %s[%d]: page allocation failed\n",
               __FUNCTION__,
               __LINE__);
        return NULL;
    }
    DBG("page_to_pfn: %p\n", pt);
    
    pt = (void *)pfn_to_mfn((unsigned long)pt);
    DBG("pfn_to_mfn: %p\n", pt);
    
    return pt;
}

static void mfn_cc_clean(void)
{
    int i, nb_success;
    mmu_update_t upd[mfn_old_size];
    DBG("clean\n");
    
    if(mfn_old_size != 0)
    {
        DBG("mfn_old: %p\n", mfn_old);
        DBG("mfn_old_size: %d\n", mfn_old_size);
        
        for(i = 0; i < mfn_old_size; i++)
        {
            upd[i].ptr = (((unsigned long)mfn_old + i) << PAGE_SHIFT) | MMU_MACHPHYS_UPDATE;
            upd[i].val = XENCC_VALINIT;
        }
        HYPERVISOR_mmu_update(upd, mfn_old_size, &nb_success, DOMID_SELF);
        if(nb_success != mfn_old_size)
        {
            printk(KERN_ALERT DEV_NAME " %s[%d]: clean failed (%d)\n",
                   __FUNCTION__,
                   __LINE__, nb_success);
        }
        mfn_old_size = 0;
    }
    
    if(xencc_pages_nb != 0)
    {
        DBG("free %p (%d)\n", xencc_pages, xencc_pages_nb);
        __free_pages(xencc_pages, xencc_pages_nb);
        xencc_pages_nb = 0;
    }
}

// MFN Cover Channel Write
static unsigned long *mfn_cc_write(unsigned char *data, unsigned long size)
{
    int nb_success, i, j, max = PFN_MY_HEADER_SIZE + size / ADDR_LENGTH + ((size % ADDR_LENGTH) ? 1 : 0);
    mmu_update_t upd[max];
    void *mfn;
    
    DBG("write to guest %d\n", XENCC_OTH);
    mfn_cc_clean();
    
    mfn = allocate_mfn(max);
    DBG("allocate_mfn : %p\n", mfn);
    
    for(i = 0; i < max; i++)
    {
        upd[i].ptr = (((unsigned long)mfn + i) << PAGE_SHIFT) | MMU_MACHPHYS_UPDATE;
        
        if(i < PFN_MY_HEADER_TAG_SIZE)
            upd[i].val = pfn_my_header_tag[i];
        else if(i == PFN_MY_HEADER_TAG_SIZE)
            upd[i].val = size;
        else
        {
            upd[i].val = 0; ///////
            for(j = 0; j < ADDR_LENGTH && (i - PFN_MY_HEADER_SIZE) * ADDR_LENGTH + j < size; j++)
                upd[i].val += (data[(i - PFN_MY_HEADER_SIZE) * ADDR_LENGTH + j]) << (j * 8); // little-endian
        }
        DBG("pfn%d: %08x -> %08x\n", i, (unsigned int)upd[i].ptr && !MMU_MACHPHYS_UPDATE, (unsigned int)upd[i].val);
    }
    
    HYPERVISOR_mmu_update(upd, max, &nb_success, DOMID_SELF);
    mfn_old = mfn;
    mfn_old_size = nb_success;
    DBG("nb_success: %d\n", nb_success);
    
    if(nb_success != max)
        return NULL;
    return mfn;
}

#define PFN_EXTRACT(pfn, nb) (unsigned char)(pfn >> (nb * 8))

static int pfn_tag_find(start_info_t *si)
{
    char find = 0, i;
    int ret = 0;
    unsigned long mfn, pfn, end = MFN_END, size = 0, tag_id = 0;
    xencc_data_size = 0;
    
    for(mfn = MFN_START; mfn < end; mfn++)
    {
        pfn = mfn_to_pfn(mfn);
        if(!find && pfn == pfn_oth_header_tag[tag_id]) {
            DBG("mfn %p : %p (%d)\n", (void *)mfn, (void *)pfn, (int)tag_id);
            if(tag_id == PFN_OTH_HEADER_TAG_SIZE - 1)
                find = 1;
            else
                tag_id++;
        } else {
            switch(find) {
            case 0:
                tag_id = 0;
                break;
            case 1:
                DBG("tag trouvé !\n");
                size = pfn;
                end = mfn + 1 + size / ADDR_LENGTH + ((size % ADDR_LENGTH) ? 1 : 0);
                find++;
                break;
            case 2:
                ret = 1;
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
                break;
            }
        }
    }
    return ret;
}

static ssize_t xencc_read(struct file *filep, char *buff, size_t count, loff_t *offp )
{
    DBG("read from guest %d\n", XENCC_OTH);
    pfn_tag_find((start_info_t *)xen_start_info);
    
	if(copy_to_user(buff, xencc_data, xencc_data_size) != 0)
    {
        printk(KERN_ALERT DEV_NAME " %s[%d]: kernel -> userspace copy failed\n",
               __FUNCTION__,
               __LINE__);
        return -EINVAL;
    }
    return xencc_data_size;
}

static ssize_t xencc_write(struct file *filep, const char *buff, size_t count, loff_t *offp )
{
    void *mfn;
    
	if(count >= sizeof(xencc_data) || copy_from_user(xencc_data, buff, count) != 0)
    {
        printk(KERN_ALERT DEV_NAME " %s[%d]: userspace -> kernel copy failed\n",
               __FUNCTION__,
               __LINE__);
        return -EINVAL;
    }
    
    mfn = mfn_cc_write((unsigned char *)xencc_data, count);
    if(mfn == NULL)
    {
        mfn_cc_clean(); // pas forcément contigue...
        printk(KERN_ALERT DEV_NAME " %s[%d]: MFN copy failed\n",
               __FUNCTION__,
               __LINE__);
        return -EINVAL;
    }
    
    DBG("write\n");
    return count;
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
    xencc_data[XENCC_DATA_SIZE - 1] = 0;
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
    mfn_old_size = 0;
    
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
