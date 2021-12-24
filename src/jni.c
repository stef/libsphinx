#include <jni.h>
#include "sphinx.h"
#include <sodium.h>

JNIEXPORT void JNICALL Java_org_hsbp_androsphinx_Sphinx_challenge(JNIEnv *env, jobject ignore, jbyteArray pwd, jbyteArray salt, jbyteArray bfac, jbyteArray chal) {
	jbyte* bufferPtrPwd = (*env)->GetByteArrayElements(env, pwd, NULL);
	jbyte* bufferPtrSalt = (*env)->GetByteArrayElements(env, salt, NULL);
	jbyte* bufferPtrBfac = (*env)->GetByteArrayElements(env, bfac, NULL);
	jbyte* bufferPtrChal = (*env)->GetByteArrayElements(env, chal, NULL);
	jsize pwdLen = (*env)->GetArrayLength(env, pwd);
	jsize saltLen = (*env)->GetArrayLength(env, salt);

	sphinx_challenge(bufferPtrPwd, pwdLen, bufferPtrSalt, saltLen, bufferPtrBfac, bufferPtrChal);

	(*env)->ReleaseByteArrayElements(env, pwd, bufferPtrPwd, JNI_ABORT);
	(*env)->ReleaseByteArrayElements(env, salt, bufferPtrSalt, JNI_ABORT);
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

JNIEXPORT jbyteArray JNICALL Java_org_hsbp_androsphinx_Sphinx_finish(JNIEnv *env, jobject ignore, jbyteArray pwd, jbyteArray bfac, jbyteArray salt, jbyteArray resp) {
	jbyte* bufferPtrPwd = (*env)->GetByteArrayElements(env, pwd, NULL);
	jbyte* bufferPtrBfac = (*env)->GetByteArrayElements(env, bfac, NULL);
	jbyte* bufferPtrSalt = (*env)->GetByteArrayElements(env, salt, NULL);
	jbyte* bufferPtrResp = (*env)->GetByteArrayElements(env, resp, NULL);
	jsize pwdLen = (*env)->GetArrayLength(env, pwd);

	jbyteArray rwd = (*env)->NewByteArray(env, SPHINX_255_SER_BYTES);
	jbyte* bufferPtrRwd = (*env)->GetByteArrayElements(env, rwd, NULL);

	int result = sphinx_finish(bufferPtrPwd, pwdLen, bufferPtrBfac, bufferPtrResp, bufferPtrSalt, bufferPtrRwd);

	(*env)->ReleaseByteArrayElements(env, rwd, bufferPtrRwd, result ? JNI_ABORT : 0);
	(*env)->ReleaseByteArrayElements(env, salt, bufferPtrSalt, JNI_ABORT);
	(*env)->ReleaseByteArrayElements(env, resp, bufferPtrResp, JNI_ABORT);
	(*env)->ReleaseByteArrayElements(env, bfac, bufferPtrBfac, JNI_ABORT);
	(*env)->ReleaseByteArrayElements(env, pwd, bufferPtrPwd, JNI_ABORT);

	return result ? NULL : rwd;
}

JNIEXPORT jbyteArray JNICALL Java_org_hsbp_androsphinx_Sodium_genericHash(JNIEnv *env, jobject ignore, jbyteArray msg, jbyteArray salt, jint outlen) {
	if (outlen <= 0) return NULL;

	jbyte* bufferPtrMsg  = (*env)->GetByteArrayElements(env, msg,  NULL);
	jbyte* bufferPtrSalt = (*env)->GetByteArrayElements(env, salt, NULL);
	jsize msgLen = (*env)->GetArrayLength(env, msg);
	jsize saltLen = (*env)->GetArrayLength(env, salt);

	jbyteArray hash = (*env)->NewByteArray(env, outlen);
	jbyte* bufferPtrHash = (*env)->GetByteArrayElements(env, hash, NULL);

	crypto_generichash(bufferPtrHash, outlen,
			bufferPtrMsg, msgLen, bufferPtrSalt, saltLen);

	(*env)->ReleaseByteArrayElements(env, msg,  bufferPtrMsg, JNI_ABORT);
	(*env)->ReleaseByteArrayElements(env, salt, bufferPtrSalt, JNI_ABORT);
	(*env)->ReleaseByteArrayElements(env, hash, bufferPtrHash, 0);

	return hash;
}

JNIEXPORT jbyteArray JNICALL Java_org_hsbp_androsphinx_Sodium_randomBytes(JNIEnv *env, jobject ignore, jint length) {
	jbyteArray result = (*env)->NewByteArray(env, length);
	jbyte* bufferPtrResult = (*env)->GetByteArrayElements(env, result, NULL);

	randombytes_buf(bufferPtrResult, length);

	(*env)->ReleaseByteArrayElements(env, result, bufferPtrResult, 0);

	return result;
}

JNIEXPORT jbyteArray JNICALL Java_org_hsbp_androsphinx_Sodium_cryptoSignSeedKeypair(JNIEnv *env, jobject ignore, jbyteArray seed) {
	unsigned char ignored_pk[crypto_sign_PUBLICKEYBYTES];

	jbyteArray result = (*env)->NewByteArray(env, crypto_sign_SECRETKEYBYTES);
	jbyte* bufferPtrResult = (*env)->GetByteArrayElements(env, result, NULL);
	jbyte* bufferPtrSeed = (*env)->GetByteArrayElements(env, seed, NULL);

	crypto_sign_seed_keypair(ignored_pk, bufferPtrResult, bufferPtrSeed);

	(*env)->ReleaseByteArrayElements(env, result, bufferPtrResult, 0);
	(*env)->ReleaseByteArrayElements(env, seed, bufferPtrSeed, JNI_ABORT);

	return result;
}

JNIEXPORT jbyteArray JNICALL Java_org_hsbp_androsphinx_Sodium_cryptoSignEd25519SkToPk(JNIEnv *env, jobject ignore, jbyteArray sk) {
	jbyteArray result = (*env)->NewByteArray(env, crypto_sign_PUBLICKEYBYTES);
	jbyte* bufferPtrResult = (*env)->GetByteArrayElements(env, result, NULL);
	jbyte* bufferPtrSk = (*env)->GetByteArrayElements(env, sk, NULL);

	crypto_sign_ed25519_sk_to_pk(bufferPtrResult, bufferPtrSk);

	(*env)->ReleaseByteArrayElements(env, result, bufferPtrResult, 0);
	(*env)->ReleaseByteArrayElements(env, sk, bufferPtrSk, JNI_ABORT);

	return result;
}

JNIEXPORT jbyteArray JNICALL Java_org_hsbp_androsphinx_Sodium_cryptoSignDetached(JNIEnv *env, jobject ignore, jbyteArray sk, jbyteArray msg) {
	jbyteArray result = (*env)->NewByteArray(env, crypto_sign_BYTES);
	jbyte* bufferPtrResult = (*env)->GetByteArrayElements(env, result, NULL);
	jbyte* bufferPtrSk = (*env)->GetByteArrayElements(env, sk, NULL);
	jbyte* bufferPtrMsg = (*env)->GetByteArrayElements(env, msg, NULL);
	jsize msgLen = (*env)->GetArrayLength(env, msg);

	unsigned long long ignored_siglen = crypto_sign_BYTES;

	crypto_sign_detached(bufferPtrResult, &ignored_siglen, bufferPtrMsg, msgLen, bufferPtrSk);

	(*env)->ReleaseByteArrayElements(env, result, bufferPtrResult, 0);
	(*env)->ReleaseByteArrayElements(env, sk, bufferPtrSk, JNI_ABORT);
	(*env)->ReleaseByteArrayElements(env, msg, bufferPtrMsg, JNI_ABORT);

	return result;
}

JNIEXPORT jbyteArray JNICALL Java_org_hsbp_androsphinx_Sodium_cryptoAeadXchachaPoly1305IetfEasy(JNIEnv *env, jobject ignore, jbyteArray msg, jbyteArray ad, jbyteArray key) {
	jbyte* bufferPtrKey = (*env)->GetByteArrayElements(env, key, NULL);
	jbyte* bufferPtrMsg = (*env)->GetByteArrayElements(env, msg, NULL);
	jbyte* bufferPtrAd  = (*env)->GetByteArrayElements(env,  ad, NULL);
	jsize msgLen = (*env)->GetArrayLength(env, msg);
	jsize  adLen = (*env)->GetArrayLength(env,  ad);

	jbyteArray result = (*env)->NewByteArray(env, crypto_aead_xchacha20poly1305_ietf_NPUBBYTES + msgLen + crypto_aead_xchacha20poly1305_ietf_ABYTES);
	jbyte* bufferPtrResult = (*env)->GetByteArrayElements(env, result, NULL);

	randombytes_buf(bufferPtrResult, crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);

	int sodium_result = crypto_aead_xchacha20poly1305_ietf_encrypt(bufferPtrResult + crypto_aead_xchacha20poly1305_ietf_NPUBBYTES,
			NULL, bufferPtrMsg, msgLen, bufferPtrAd, adLen, NULL, bufferPtrResult, bufferPtrKey);

	(*env)->ReleaseByteArrayElements(env, result, bufferPtrResult, sodium_result ? JNI_ABORT : 0);
	(*env)->ReleaseByteArrayElements(env,  ad, bufferPtrAd , JNI_ABORT);
	(*env)->ReleaseByteArrayElements(env, msg, bufferPtrMsg, JNI_ABORT);
	(*env)->ReleaseByteArrayElements(env, key, bufferPtrKey, JNI_ABORT);

	return sodium_result ? NULL : result;
}

JNIEXPORT jbyteArray JNICALL Java_org_hsbp_androsphinx_Sodium_cryptoAeadXchachaPoly1305IetfOpenEasy(JNIEnv *env, jobject ignore, jbyteArray msg, jbyteArray ad, jbyteArray key) {
	jbyte* bufferPtrKey = (*env)->GetByteArrayElements(env, key, NULL);
	jbyte* bufferPtrMsg = (*env)->GetByteArrayElements(env, msg, NULL);
	jbyte* bufferPtrAd  = (*env)->GetByteArrayElements(env,  ad, NULL);
	jsize msgLen = (*env)->GetArrayLength(env, msg);
	jsize  adLen = (*env)->GetArrayLength(env,  ad);

	jbyteArray result = (*env)->NewByteArray(env, msgLen - (crypto_aead_xchacha20poly1305_ietf_NPUBBYTES + crypto_aead_xchacha20poly1305_ietf_ABYTES));
	jbyte* bufferPtrResult = (*env)->GetByteArrayElements(env, result, NULL);

	int sodium_result = crypto_aead_xchacha20poly1305_ietf_decrypt(bufferPtrResult,
			NULL, NULL, bufferPtrMsg + crypto_aead_xchacha20poly1305_ietf_NPUBBYTES,
			msgLen - crypto_aead_xchacha20poly1305_ietf_NPUBBYTES,
			bufferPtrAd, adLen, bufferPtrMsg, bufferPtrKey);

	(*env)->ReleaseByteArrayElements(env, result, bufferPtrResult, sodium_result ? JNI_ABORT : 0);
	(*env)->ReleaseByteArrayElements(env,  ad, bufferPtrAd , JNI_ABORT);
	(*env)->ReleaseByteArrayElements(env, msg, bufferPtrMsg, JNI_ABORT);
	(*env)->ReleaseByteArrayElements(env, key, bufferPtrKey, JNI_ABORT);

	return sodium_result ? NULL : result;
}
