<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0">
	<!-- this template appends the URL to the external link text -->
    <xsl:template match="ulink">
        <xsl:apply-templates/><xsl:text> &lt;</xsl:text><xsl:value-of select="@url"/><xsl:text>&gt;</xsl:text>
    </xsl:template>

    <!-- this template emphasizes the internal link text -->
    <xsl:template match="link">
        <xsl:text>\fI</xsl:text><xsl:value-of select="."/><xsl:text>\fR</xsl:text>
    </xsl:template>
</xsl:stylesheet>
