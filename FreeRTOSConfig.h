#ifndef FREERTOS_CONFIG_H
#define FREERTOS_CONFIG_H

#define configUSE_PREEMPTION 1
#define configUSE_IDLE_HOOK 0
#define configUSE_TICK_HOOK 0
#define configMAX_PRIORITIES (56)
#define configMINIMAL_STACK_SIZE ((uint16_t)128)
#define configUSE_16_BIT_TICKS 0

#endif /* FREERTOS_CONFIG_H */
