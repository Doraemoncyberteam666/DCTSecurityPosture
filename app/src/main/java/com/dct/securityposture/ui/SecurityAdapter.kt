package com.dct.securityposture.ui

import android.graphics.Color
import android.graphics.Typeface
import android.view.Gravity
import android.view.ViewGroup
import android.widget.CheckBox
import android.widget.LinearLayout
import android.widget.TextView
import androidx.recyclerview.widget.RecyclerView
import com.dct.securityposture.model.SecurityCheck
import com.dct.securityposture.model.Severity

class SecurityAdapter(private var items: List<SecurityCheck>) : RecyclerView.Adapter<SecurityAdapter.Holder>() {

    fun update(newItems: List<SecurityCheck>) {
        items = newItems
        notifyDataSetChanged()
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): Holder {
        val density = parent.resources.displayMetrics.density
        fun dp(v: Int) = (v * density).toInt()

        val root = LinearLayout(parent.context).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(16), dp(14), dp(16), dp(14))
            layoutParams = ViewGroup.MarginLayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply { setMargins(dp(12), dp(6), dp(12), dp(6)) }
            setBackgroundColor(Color.rgb(18, 24, 38))
        }

        val top = LinearLayout(parent.context).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
        }

        val cb = CheckBox(parent.context).apply {
            isClickable = false
            isFocusable = false
        }

        val title = TextView(parent.context).apply {
            setTextColor(Color.WHITE)
            textSize = 16f
            typeface = Typeface.DEFAULT_BOLD
            layoutParams = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f)
        }

        val severity = TextView(parent.context).apply {
            textSize = 12f
            typeface = Typeface.DEFAULT_BOLD
            gravity = Gravity.CENTER
            setPadding(dp(8), dp(3), dp(8), dp(3))
        }

        val summary = TextView(parent.context).apply {
            setTextColor(Color.rgb(203, 213, 225))
            textSize = 14f
            setPadding(0, dp(6), 0, 0)
        }

        val details = TextView(parent.context).apply {
            setTextColor(Color.rgb(148, 163, 184))
            textSize = 12f
            setPadding(0, dp(6), 0, 0)
        }

        top.addView(cb)
        top.addView(title)
        top.addView(severity)
        root.addView(top)
        root.addView(summary)
        root.addView(details)
        return Holder(root, cb, title, severity, summary, details)
    }

    override fun onBindViewHolder(holder: Holder, position: Int) {
        val item = items[position]
        holder.checkBox.isChecked = item.passed
        holder.title.text = item.title
        holder.summary.text = item.summary
        holder.details.text = item.details
        holder.severity.text = if (item.passed) "PASS" else item.severity.name
        holder.severity.setTextColor(Color.WHITE)
        holder.severity.setBackgroundColor(colorFor(item))
    }

    override fun getItemCount(): Int = items.size

    private fun colorFor(item: SecurityCheck): Int {
        if (item.passed) return Color.rgb(22, 163, 74)
        return when (item.severity) {
            Severity.INFO -> Color.rgb(71, 85, 105)
            Severity.LOW -> Color.rgb(101, 163, 13)
            Severity.MEDIUM -> Color.rgb(217, 119, 6)
            Severity.HIGH -> Color.rgb(220, 38, 38)
            Severity.CRITICAL -> Color.rgb(127, 29, 29)
        }
    }

    class Holder(
        root: LinearLayout,
        val checkBox: CheckBox,
        val title: TextView,
        val severity: TextView,
        val summary: TextView,
        val details: TextView
    ) : RecyclerView.ViewHolder(root)
}
