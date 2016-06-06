#ifndef _ASM_X86_IO_H_
#define _ASM_X86_IO_H_

#define __iomem

static inline unsigned char inb(unsigned short port)
{
    unsigned char value;
    asm volatile("inb %w1, %0" : "=a" (value) : "Nd" (port));
    return value;
}

static inline unsigned short inw(unsigned short port)
{
    unsigned short value;
    asm volatile("inw %w1, %0" : "=a" (value) : "Nd" (port));
    return value;
}

static inline unsigned int inl(unsigned short port)
{
    unsigned int value;
    asm volatile("inl %w1, %0" : "=a" (value) : "Nd" (port));
    return value;
}

static inline void outb(unsigned char value, unsigned short port)
{
    asm volatile("outb %b0, %w1" : : "a"(value), "Nd"(port));
}

static inline void outw(unsigned short value, unsigned short port)
{
    asm volatile("outw %w0, %w1" : : "a"(value), "Nd"(port));
}

static inline void outl(unsigned int value, unsigned short port)
{
    asm volatile("outl %0, %w1" : : "a"(value), "Nd"(port));
}

static inline unsigned long virt_to_phys(const void *virt)
{
    return (unsigned long)virt;
}

static inline void *phys_to_virt(unsigned long phys)
{
    return (void *)phys;
}

void __iomem *ioremap(phys_addr_t phys_addr, size_t size);

#endif
