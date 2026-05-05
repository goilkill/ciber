package com.digitalsignature.service

import com.digitalsignature.model.KeyPairResponse
import com.digitalsignature.model.SignatureMetadata
import com.digitalsignature.model.VerifyResponse
import com.fasterxml.jackson.databind.ObjectMapper
import org.springframework.stereotype.Service
import java.io.ByteArrayOutputStream
import java.security.*
import java.security.spec.ECGenParameterSpec
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import java.time.Instant
import java.util.Base64
import java.util.zip.ZipEntry
import java.util.zip.ZipInputStream
import java.util.zip.ZipOutputStream

@Service
class SignatureService(private val objectMapper: ObjectMapper) {

    fun generateKeys(algorithm: String): KeyPairResponse {
        val keyPair = when (algorithm.uppercase()) {
            "RSA" -> KeyPairGenerator.getInstance("RSA")
                .apply { initialize(2048) }
                .generateKeyPair()
            "ECDSA" -> KeyPairGenerator.getInstance("EC")
                .apply { initialize(ECGenParameterSpec("secp256r1"), SecureRandom()) }
                .generateKeyPair()
            else -> throw IllegalArgumentException("Unsupported algorithm: $algorithm. Use RSA or ECDSA.")
        }
        return KeyPairResponse(
            publicKey = Base64.getEncoder().encodeToString(keyPair.public.encoded),
            privateKey = Base64.getEncoder().encodeToString(keyPair.private.encoded),
            algorithm = algorithm.uppercase()
        )
    }

    fun signDocument(
        fileBytes: ByteArray,
        fileName: String,
        privateKeyBase64: String,
        publicKeyBase64: String,
        encryptionAlgorithm: String,
        hashAlgorithm: String
    ): ByteArray {
        val algo = encryptionAlgorithm.uppercase()

        if (algo == "ECDSA" && hashAlgorithm == "MD5") {
            throw IllegalArgumentException("MD5 is not supported with ECDSA. Use RSA or choose SHA-256/SHA-512.")
        }

        val privateKeyBytes = Base64.getDecoder().decode(privateKeyBase64.trim())
        val privateKey = when (algo) {
            "RSA" -> KeyFactory.getInstance("RSA").generatePrivate(PKCS8EncodedKeySpec(privateKeyBytes))
            "ECDSA" -> KeyFactory.getInstance("EC").generatePrivate(PKCS8EncodedKeySpec(privateKeyBytes))
            else -> throw IllegalArgumentException("Unsupported encryption algorithm: $algo")
        }

        // Hash the file for metadata (informational)
        val digestName = hashAlgorithm.replace("-", "")
        val fileHashHex = MessageDigest.getInstance(digestName)
            .digest(fileBytes)
            .joinToString("") { "%02x".format(it) }

        // Sign: the JCA Signature object internally hashes + signs
        val jceAlgo = buildJceAlgorithm(hashAlgorithm, algo)
        val sig = Signature.getInstance(jceAlgo)
        sig.initSign(privateKey)
        sig.update(fileBytes)
        val signatureBytes = sig.sign()

        val metadata = SignatureMetadata(
            algorithm = "$algo-$hashAlgorithm",
            hashAlgorithm = hashAlgorithm,
            encryptionAlgorithm = algo,
            signature = Base64.getEncoder().encodeToString(signatureBytes),
            publicKey = publicKeyBase64.trim(),
            timestamp = Instant.now().toString(),
            originalFileName = fileName,
            originalFileHash = fileHashHex
        )

        // Package: original file (unchanged) + metadata.json → ZIP
        val baos = ByteArrayOutputStream()
        ZipOutputStream(baos).use { zos ->
            zos.putNextEntry(ZipEntry("original/$fileName"))
            zos.write(fileBytes)
            zos.closeEntry()

            zos.putNextEntry(ZipEntry("metadata.json"))
            zos.write(objectMapper.writerWithDefaultPrettyPrinter().writeValueAsBytes(metadata))
            zos.closeEntry()
        }
        return baos.toByteArray()
    }

    fun verifyDocument(zipBytes: ByteArray, publicKeyBase64: String?): VerifyResponse {
        val entries = mutableMapOf<String, ByteArray>()
        ZipInputStream(zipBytes.inputStream()).use { zis ->
            var entry = zis.nextEntry
            while (entry != null) {
                entries[entry.name] = zis.readBytes()
                entry = zis.nextEntry
            }
        }

        val metadataBytes = entries["metadata.json"]
            ?: return VerifyResponse(valid = false, details = "Invalid signed document: metadata.json not found.")

        val metadata = objectMapper.readValue(metadataBytes, SignatureMetadata::class.java)

        val originalKey = entries.keys.firstOrNull { it.startsWith("original/") }
            ?: return VerifyResponse(valid = false, details = "Invalid signed document: original file not found.")

        val originalBytes = entries[originalKey]!!

        val pubKeyBase64 = publicKeyBase64?.trim()?.takeIf { it.isNotBlank() } ?: metadata.publicKey

        return try {
            val pubKeyBytes = Base64.getDecoder().decode(pubKeyBase64)
            val publicKey = when (metadata.encryptionAlgorithm) {
                "RSA" -> KeyFactory.getInstance("RSA").generatePublic(X509EncodedKeySpec(pubKeyBytes))
                "ECDSA" -> KeyFactory.getInstance("EC").generatePublic(X509EncodedKeySpec(pubKeyBytes))
                else -> throw IllegalArgumentException("Unknown algorithm: ${metadata.encryptionAlgorithm}")
            }

            val jceAlgo = buildJceAlgorithm(metadata.hashAlgorithm, metadata.encryptionAlgorithm)
            val sig = Signature.getInstance(jceAlgo)
            sig.initVerify(publicKey)
            sig.update(originalBytes)

            val valid = sig.verify(Base64.getDecoder().decode(metadata.signature))

            VerifyResponse(
                valid = valid,
                fileName = metadata.originalFileName,
                algorithm = metadata.algorithm,
                hashAlgorithm = metadata.hashAlgorithm,
                timestamp = metadata.timestamp,
                details = if (valid)
                    "Signature is VALID. The document has not been modified since signing."
                else
                    "Signature is INVALID. The document may have been tampered with."
            )
        } catch (e: Exception) {
            VerifyResponse(valid = false, details = "Verification error: ${e.message}")
        }
    }

    private fun buildJceAlgorithm(hashAlgorithm: String, encryptionAlgorithm: String): String {
        val hash = hashAlgorithm.replace("-", "")
        return "${hash}with${encryptionAlgorithm}"
    }
}
