package com.digitalsignature.service

import com.digitalsignature.model.WeakAttackResponse
import org.springframework.stereotype.Service

@Service
class WeakDemoService {

    private fun weakHash(input: ByteArray): Int =
        input.fold(0) { acc, b -> (acc + (b.toInt() and 0xFF)) % 256 }

    private fun toHex(value: Int): String = value.toString(16).padStart(2, '0').uppercase()

    fun demonstrateCollision(inputText: String): WeakAttackResponse {
        val originalBytes = inputText.toByteArray()
        val targetHash = weakHash(originalBytes)

        val maliciousPrefix = "TAMPERED: $inputText"
        val prefixBytes = maliciousPrefix.toByteArray()
        val prefixHash = weakHash(prefixBytes)

        val adjustByte = ((targetHash - prefixHash) + 256) % 256
        val maliciousBytes = prefixBytes + byteArrayOf(adjustByte.toByte())
        val collidingHash = weakHash(maliciousBytes)

        val explanation = """
Наш слабый алгоритм суммирует все байты документа и берёт остаток от деления на 256.
Результат: всего 256 возможных значений хеша (1 байт).

Атака (O(1), мгновенная):
1. Берём любой другой текст: "TAMPERED: ..."
2. Вычисляем его хеш
3. Добавляем один байт-поправку так, чтобы итоговый хеш совпал с оригинальным

Итог: подпись будет ВАЛИДНА для подменённого документа!
Это означает: злоумышленник может подменить документ, и проверка подписи пройдёт успешно.

Для сравнения — SHA-256 имеет 2^256 ≈ 10^77 возможных значений.
Найти коллизию в SHA-256 перебором невозможно даже за миллиарды лет.
        """.trimIndent()

        return WeakAttackResponse(
            success = collidingHash == targetHash,
            attackType = "Collision Attack — O(1), мгновенно",
            explanation = explanation,
            originalInput = inputText,
            originalHash = toHex(targetHash),
            collidingInput = maliciousPrefix + " [+0x${toHex(adjustByte)}]",
            collidingHash = toHex(collidingHash)
        )
    }

    fun getWeakAlgorithmInfo(): Map<String, Any> = mapOf(
        "name" to "Custom Weak Hash (Sum mod 256)",
        "outputBits" to 8,
        "possibleValues" to 256,
        "vulnerability" to "Only 256 possible hash values — collisions trivially found in O(1)",
        "comparison" to mapOf(
            "SHA-256" to mapOf("bits" to 256, "values" to "2^256 ≈ 10^77", "safe" to true),
            "SHA-512" to mapOf("bits" to 512, "values" to "2^512", "safe" to true),
            "MD5" to mapOf("bits" to 128, "values" to "2^128", "safe" to false, "reason" to "Known collisions exist"),
            "SHA-1" to mapOf("bits" to 160, "values" to "2^160", "safe" to false, "reason" to "Broken by SHAttered attack (2017)"),
            "WeakHash" to mapOf("bits" to 8, "values" to "256", "safe" to false, "reason" to "Trivially breakable")
        )
    )
}
