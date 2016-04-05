<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0">
	<!-- this template cancels the style of literal elements in title elements -->
    <xsl:template match="title/literal">
        <xsl:value-of select="."/>
    </xsl:template>
</xsl:stylesheet>
