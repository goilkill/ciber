package com.digitalsignature.controller

import com.digitalsignature.service.SignatureService
import com.digitalsignature.service.WeakDemoService
import org.springframework.http.HttpHeaders
import org.springframework.http.MediaType
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.*
import org.springframework.web.multipart.MultipartFile

@RestController
@RequestMapping("/api")
class SignatureController(
    private val signatureService: SignatureService,
    private val weakDemoService: WeakDemoService
) {

    @ExceptionHandler(Exception::class)
    fun handleError(e: Exception): ResponseEntity<Map<String, String>> =
        ResponseEntity.badRequest().body(mapOf("error" to (e.message ?: "Unknown error")))

    @PostMapping("/generate-keys")
    fun generateKeys(@RequestBody body: Map<String, String>): ResponseEntity<Any> {
        val algorithm = body["algorithm"] ?: throw IllegalArgumentException("algorithm is required")
        return ResponseEntity.ok(signatureService.generateKeys(algorithm))
    }

    @PostMapping("/sign", consumes = [MediaType.MULTIPART_FORM_DATA_VALUE])
    fun signDocument(
        @RequestPart("file") file: MultipartFile,
        @RequestParam("privateKey") privateKey: String,
        @RequestParam("publicKey") publicKey: String,
        @RequestParam("encryptionAlgorithm") encryptionAlgorithm: String,
        @RequestParam("hashAlgorithm") hashAlgorithm: String
    ): ResponseEntity<ByteArray> {
        val originalName = file.originalFilename ?: "document"
        val signedBytes = signatureService.signDocument(
            fileBytes = file.bytes,
            fileName = originalName,
            privateKeyBase64 = privateKey,
            publicKeyBase64 = publicKey,
            encryptionAlgorithm = encryptionAlgorithm,
            hashAlgorithm = hashAlgorithm
        )
        return ResponseEntity.ok()
            .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"${originalName}.signed.zip\"")
            .contentType(MediaType.APPLICATION_OCTET_STREAM)
            .body(signedBytes)
    }

    @PostMapping("/verify", consumes = [MediaType.MULTIPART_FORM_DATA_VALUE])
    fun verifyDocument(
        @RequestPart("file") file: MultipartFile,
        @RequestParam(value = "publicKey", required = false) publicKey: String?
    ): ResponseEntity<Any> {
        val result = signatureService.verifyDocument(file.bytes, publicKey)
        return ResponseEntity.ok(result)
    }

    @PostMapping("/weak/attack")
    fun weakAttack(@RequestBody body: Map<String, String>): ResponseEntity<Any> {
        val input = body["input"]?.takeIf { it.isNotBlank() }
            ?: throw IllegalArgumentException("input text is required")
        return ResponseEntity.ok(weakDemoService.demonstrateCollision(input))
    }

    @GetMapping("/weak/info")
    fun weakInfo(): ResponseEntity<Any> =
        ResponseEntity.ok(weakDemoService.getWeakAlgorithmInfo())
}
