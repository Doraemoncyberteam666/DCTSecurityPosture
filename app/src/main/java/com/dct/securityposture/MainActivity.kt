package com.dct.securityposture

import android.graphics.Color
import android.graphics.Typeface
import android.os.Bundle
import android.view.Gravity
import android.view.ViewGroup
import android.widget.Button
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.dct.securityposture.model.SecurityCheck
import com.dct.securityposture.security.SecurityChecks
import com.dct.securityposture.ui.SecurityAdapter

class MainActivity : AppCompatActivity() {
    private lateinit var adapter: SecurityAdapter
    private lateinit var summaryView: TextView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        buildUi()
        runChecks()
    }

    private fun buildUi() {
        val density = resources.displayMetrics.density
        fun dp(v: Int) = (v * density).toInt()

        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setBackgroundColor(Color.rgb(9, 11, 16))
            setPadding(0, dp(16), 0, 0)
        }

        val title = TextView(this).apply {
            text = "DCT Security Posture"
            setTextColor(Color.WHITE)
            textSize = 24f
            typeface = Typeface.DEFAULT_BOLD
            setPadding(dp(16), 0, dp(16), 0)
        }

        summaryView = TextView(this).apply {
            setTextColor(Color.rgb(203, 213, 225))
            textSize = 14f
            setPadding(dp(16), dp(6), dp(16), dp(12))
        }

        val refresh = Button(this).apply {
            text = "Run checks again"
            setOnClickListener { runChecks() }
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply { setMargins(dp(16), 0, dp(16), dp(10)) }
        }

        val recycler = RecyclerView(this).apply {
            layoutManager = LinearLayoutManager(this@MainActivity)
            adapter = SecurityAdapter(emptyList()).also { this@MainActivity.adapter = it }
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                0,
                1f
            )
        }

        root.addView(title)
        root.addView(summaryView)
        root.addView(refresh)
        root.addView(recycler)
        setContentView(root)
    }

    private fun runChecks() {
        val checks = SecurityChecks.runAll(this)
        adapter.update(checks)
        summaryView.text = buildSummary(checks)
    }

    private fun buildSummary(checks: List<SecurityCheck>): String {
        val failed = checks.count { !it.passed }
        val passed = checks.count { it.passed }
        val total = checks.size
        val highest = checks.filter { !it.passed }.maxByOrNull { it.severity.ordinal }?.severity?.name ?: "NONE"
        val source = checks.firstOrNull { it.title == "Install source" }?.summary ?: "Install source unavailable"
        return "Passed: $passed / $total  •  Failed: $failed  •  Highest: $highest\n$source"
    }
}
