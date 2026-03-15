package app.pwhs.blockads.data.repository

import timber.log.Timber
import java.io.BufferedReader

/**
 * Parses EasyList-format cosmetic filter rules and produces a minified CSS stylesheet.
 *
 * Supported input formats:
 *   ##.ad-box                → generic rule (applies to all sites)
 *   ##div[id^="ad-"]         → generic rule with attribute selector
 *   ##.ad-box,.ad-banner     → generic rule with multiple selectors
 *
 * Ignored:
 *   example.com##.sidebar    → domain-specific (V2)
 *   #@#.ad-box               → exception rule
 *   ##+js(...)               → scriptlet injection (unsupported)
 *   ##^.ad                   → HTML filtering (unsupported)
 *   Lines starting with ! or # (comments)
 */
object CosmeticRuleParser {

    private const val MAX_RULES = 2000

    /**
     * Parse lines from a filter list and return a minified CSS string.
     *
     * Each generic cosmetic rule is converted to:
     *   selector { display: none !important; }
     *
     * @param reader A [BufferedReader] for the filter file.
     * @return Minified CSS string ready for injection, or empty string if no rules found.
     */
    fun parseToCss(reader: BufferedReader): String {
        val selectors = mutableListOf<String>()

        reader.lineSequence()
            .filter { line ->
                val trimmed = line.trim()
                // Skip obvious comments
                if ((trimmed.startsWith("! ") || trimmed.startsWith("# ")) && !trimmed.contains("##")) {
                    return@filter false
                }
                
                // Must contain ##
                trimmed.contains("##") &&
                        !trimmed.contains("#@#") &&
                        // Exclude scriptlet injection (##+js)
                        !trimmed.contains("##+js") &&
                        // Exclude HTML filtering (##^)
                        !trimmed.contains("##^")
            }
            .forEach { line ->
                val trimmed = line.trim()
                val idx = trimmed.indexOf("##")
                if (idx < 0) return@forEach

                val prefix = trimmed.substring(0, idx)
                val selector = trimmed.substring(idx + 2).trim()

                // V1: Only generic rules (no domain prefix)
                if (prefix.isNotEmpty()) return@forEach

                // Validate selector is not empty and looks reasonable
                if (selector.isEmpty()) return@forEach
                if (selector.startsWith('+') || selector.startsWith('^')) return@forEach
                
                // Exclude selectors with unescaped spaces as they are usually comments parsing errors (e.g. `### Version`)
                if (selector.contains(" ")) return@forEach
                
                // Exclude comment separators that slipped through like `###############`
                if (!selector.any { it.isLetterOrDigit() }) return@forEach

                // Avoid injecting selectors with potentially dangerous content
                if (selector.contains("url(") || selector.contains("expression(")) return@forEach

                if (selectors.size < MAX_RULES) {
                    selectors.add(selector)
                }
            }

        if (selectors.isEmpty()) return ""

        Timber.d("Parsed ${selectors.size} cosmetic rules (capped at $MAX_RULES)")

        // Build minified CSS: group selectors and apply display:none
        // Group in batches of 50 selectors per rule to keep each rule manageable
        val sb = StringBuilder()
        selectors.chunked(50).forEach { batch ->
            sb.append(batch.joinToString(","))
            sb.append("{display:none!important}")
        }

        return sb.toString()
    }

    /**
     * Parse cosmetic rules from a list of strings (for testing or in-memory use).
     *
     * @param lines List of filter list lines.
     * @return Minified CSS string.
     */
    fun parseToCss(lines: List<String>): String {
        return parseToCss(lines.joinToString("\n").reader().buffered())
    }
}
