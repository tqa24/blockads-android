package app.pwhs.blockads.data.repository

import org.junit.Assert.assertEquals
import org.junit.Test

class CosmeticRuleParserTest {

    @Test
    fun parseToCss_generatesMinifiedCss_forGenericRules() {
        val rules = listOf(
            "##.ad-box",
            "##div[id^=\"ad-\"]",
            "##.sidebar-sponsor",
            "###ADbox", // Tests ID selector (3 hashes total)
            "! This is a comment",
            "example.com##.domain-specific-rule", // Extracted out in V1
            "#@#.exception-rule", // Excluded
            "##+js(scriptlet)", // Excluded
            "##^.html-filtering" // Excluded
        )

        val css = CosmeticRuleParser.parseToCss(rules)

        // Expected output: generic rules grouped by 50, with display:none!important
        val expected = ".ad-box,div[id^=\"ad-\"],.sidebar-sponsor,#ADbox{display:none!important}"

        assertEquals(expected, css)
    }

    @Test
    fun parseToCss_limitsOutputToMaxRules() {
        val rules = mutableListOf<String>()
        // Create 2050 valid rules
        for (i in 1..2050) {
            rules.add("##.ad-banner-$i")
        }

        val css = CosmeticRuleParser.parseToCss(rules)

        // Should only contain up to max (2000).
        // Since chunks of 50 are merged, the string will contain 40 occurrences of {display:none!important}
        val blockCount = css.split("{display:none!important}").size - 1
        assertEquals(40, blockCount)
        
        // Assert that the 2001st rule is NOT present
        assertEquals(false, css.contains(".ad-banner-2001"))
    }
}
