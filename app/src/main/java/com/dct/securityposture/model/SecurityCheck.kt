package com.dct.securityposture.model

data class SecurityCheck(
    val title: String,
    val passed: Boolean,
    val severity: Severity,
    val summary: String,
    val details: String,
    val category: String
)

enum class Severity { INFO, LOW, MEDIUM, HIGH, CRITICAL }
