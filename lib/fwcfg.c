
void qemu_cfg_select(int f)
{
    outw(QEMU_CFG_CTL_PORT, f);
}

int qemu_cfg_port_probe()
{
    char *sig = "QEMU";
    int i;

    qemu_cfg_select(QEMU_CFG_SIGNATURE);

    for (i = 0; i < 4; i++)
        if (inb(QEMU_CFG_DATA_PORT) != sig[i])
            return 0;

    return 1;
}

void qemu_cfg_read(uint8_t *buf, int len)
{
    while (len--)
        *(buf++) = inb(QEMU_CFG_DATA_PORT);
}

uint8_t qemu_cfg_get8(void)
{
    uint8_t ret;

    qemu_cfg_read(&ret, 1);
    return ret;
}

uint16_t qemu_cfg_get16(void)
{
    uint16_t ret;

    qemu_cfg_read((uint8_t*)&ret, 2);
    return le16_to_cpu(ret);
}

uint64_t qemu_cfg_get32(void)
{
    uint32_t ret;

    qemu_cfg_read((uint8_t*)&ret, 4);
    return le32_to_cpu(ret);
}

uint64_t qemu_cfg_get64(void)
{
    uint64_t ret;

    qemu_cfg_read((uint8_t*)&ret, 8);
    return le64_to_cpu(ret);
}

