obj-m += xencc.o

VERSION = $(shell uname -r)
#VERSION = 2.6.18-6-xen-686

SRC = /lib/modules/$(VERSION)/build

default:
	make -C $(SRC) M=$(PWD) modules

clean:
	make -C $(SRC) M=$(PWD) clean
