#ifndef PORTMACRO_H
#define PORTMACRO_H

#define portSTACK_TYPE	uint32_t

typedef portSTACK_TYPE StackType_t;
typedef long BaseType_t;
typedef unsigned long UBaseType_t;

typedef uint32_t TickType_t;

#define portBYTE_ALIGNMENT 8

#endif /* PORTMACRO_H */
