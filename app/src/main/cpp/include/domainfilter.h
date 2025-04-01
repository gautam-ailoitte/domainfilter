// domainfilter.h
#ifndef DOMAINFILTER_H
#define DOMAINFILTER_H

#include <jni.h>
#include <stddef.h> // for size_t

#ifdef __cplusplus
extern "C" {
#endif

// Domain extraction
int extract_domain_from_packet(const void *packet, size_t len, char *domain, size_t domain_size);

// Domain filtering
void filter_init();
void filter_cleanup();
void filter_add_domain(const char *domain);
int filter_load_file(const char *filename);
int filter_check_domain(const char *domain);

// JNI functions for VPN service
JNIEXPORT void JNICALL
Java_com_example_domainfilter_FilterVpnService_jniInit(JNIEnv *env, jobject thiz);

JNIEXPORT void JNICALL
Java_com_example_domainfilter_FilterVpnService_jniStart(JNIEnv *env, jobject thiz, jint fd);

JNIEXPORT void JNICALL
Java_com_example_domainfilter_FilterVpnService_jniStop(JNIEnv *env, jobject thiz);

JNIEXPORT jint JNICALL
Java_com_example_domainfilter_FilterVpnService_jniGetFilteredCount(JNIEnv *env, jobject thiz);

// JNI functions for filter manager
JNIEXPORT void JNICALL
Java_com_example_domainfilter_util_FilterManager_jniInitFilter(JNIEnv *env, jobject thiz);

JNIEXPORT void JNICALL
Java_com_example_domainfilter_util_FilterManager_jniAddDomain(JNIEnv *env, jobject thiz, jstring domain);

JNIEXPORT void JNICALL
Java_com_example_domainfilter_util_FilterManager_jniLoadFilterFile(JNIEnv *env, jobject thiz, jstring filePath);

JNIEXPORT jboolean JNICALL
Java_com_example_domainfilter_util_FilterManager_jniCheckDomain(JNIEnv *env, jobject thiz, jstring domain);

#ifdef __cplusplus
}
#endif

#endif // DOMAINFILTER_H