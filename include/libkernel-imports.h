#define LIBKERNEL_HANDLE 0x2001

API(void, sceKernelSendNotificationRequest,
    (int32_t device, NotificationRequest *req, size_t size, int32_t blocking))
API(int, sysctlbyname,
    (const char *name, void *oldp, size_t *oldlenp, const void *newp,
     size_t newlen))