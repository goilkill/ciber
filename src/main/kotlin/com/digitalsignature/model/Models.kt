package com.digitalsignature.model

data class KeyPairResponse(
    val publicKey: String,
    val privateKey: String,
    val algorithm: String
)

data class VerifyResponse(
    val valid: Boolean,
    val fileName: String? = null,
    val algorithm: String? = null,
    val hashAlgorithm: String? = null,
    val timestamp: String? = null,
    val details: String
)

data class WeakAttackResponse(
    val success: Boolean,
    val attackType: String,
    val explanation: String,
    val originalInput: String,
    val originalHash: String,
    val collidingInput: String,
    val collidingHash: String
)

data class SignatureMetadata(
    val signatureVersion: String = "1.0",
    val algorithm: String,
    val hashAlgorithm: String,
    val encryptionAlgorithm: String,
    val signature: String,
    val publicKey: String,
    val timestamp: String,
    val originalFileName: String,
    val originalFileHash: String
)
