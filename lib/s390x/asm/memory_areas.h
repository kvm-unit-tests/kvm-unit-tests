#ifndef MEMORY_AREAS_H
#define MEMORY_AREAS_H

#define AREA_NORMAL_PFN BIT(31-12)
#define AREA_NORMAL_NUMBER 0
#define AREA_NORMAL 1

#define AREA_LOW_PFN 0
#define AREA_LOW_NUMBER 1
#define AREA_LOW 2

#define AREA_ANY -1
#define AREA_ANY_NUMBER 0xff

#define AREA_DMA31 AREA_LOW

#endif
