#include <jni.h>
#include "sphinx.h"

JNIEXPORT void JNICALL Java_org_hsbp_androsphinx_Sphinx_challenge(JNIEnv *env, jobject ignore, jbyteArray pwd, jbyteArray bfac, jbyteArray chal) {
	jbyte* bufferPtrPwd = (*env)->GetByteArrayElements(env, pwd, NULL);
	jbyte* bufferPtrBfac = (*env)->GetByteArrayElements(env, bfac, NULL);
	jbyte* bufferPtrChal = (*env)->GetByteArrayElements(env, chal, NULL);
	jsize pwdLen = (*env)->GetArrayLength(env, pwd);

	sphinx_challenge(bufferPtrPwd, pwdLen, bufferPtrBfac, bufferPtrChal);

	(*env)->ReleaseByteArrayElements(env, pwd, bufferPtrPwd, JNI_ABORT);
	(*env)->ReleaseByteArrayElements(env, bfac, bufferPtrBfac, 0);
	(*env)->ReleaseByteArrayElements(env, chal, bufferPtrChal, 0);
}

JNIEXPORT jbyteArray JNICALL Java_org_hsbp_androsphinx_Sphinx_respond(JNIEnv *env, jobject ignore, jbyteArray chal, jbyteArray secret) {
	jbyte* bufferPtrChal = (*env)->GetByteArrayElements(env, chal, NULL);
	jbyte* bufferPtrSecret = (*env)->GetByteArrayElements(env, secret, NULL);

	jbyteArray resp = (*env)->NewByteArray(env, SPHINX_255_SER_BYTES);
	jbyte* bufferPtrResp = (*env)->GetByteArrayElements(env, resp, NULL);

	int result = sphinx_respond(bufferPtrChal, bufferPtrSecret, bufferPtrResp);

	(*env)->ReleaseByteArrayElements(env, resp, bufferPtrResp, result ? JNI_ABORT : 0);
	(*env)->ReleaseByteArrayElements(env, chal, bufferPtrChal, JNI_ABORT);
	(*env)->ReleaseByteArrayElements(env, secret, bufferPtrSecret, JNI_ABORT);

	return result ? NULL : resp;
}

JNIEXPORT jbyteArray JNICALL Java_org_hsbp_androsphinx_Sphinx_finish(JNIEnv *env, jobject ignore, jbyteArray pwd, jbyteArray bfac, jbyteArray resp) {
	jbyte* bufferPtrPwd = (*env)->GetByteArrayElements(env, pwd, NULL);
	jbyte* bufferPtrBfac = (*env)->GetByteArrayElements(env, bfac, NULL);
	jbyte* bufferPtrResp = (*env)->GetByteArrayElements(env, resp, NULL);
	jsize pwdLen = (*env)->GetArrayLength(env, pwd);

	jbyteArray rwd = (*env)->NewByteArray(env, SPHINX_255_SER_BYTES);
	jbyte* bufferPtrRwd = (*env)->GetByteArrayElements(env, rwd, NULL);

	int result = sphinx_finish(bufferPtrPwd, pwdLen, bufferPtrBfac, bufferPtrResp, bufferPtrRwd);

	(*env)->ReleaseByteArrayElements(env, rwd, bufferPtrRwd, result ? JNI_ABORT : 0);
	(*env)->ReleaseByteArrayElements(env, resp, bufferPtrResp, JNI_ABORT);
	(*env)->ReleaseByteArrayElements(env, bfac, bufferPtrBfac, JNI_ABORT);
	(*env)->ReleaseByteArrayElements(env, pwd, bufferPtrPwd, JNI_ABORT);

	return result ? NULL : rwd;
}
