#ifndef UST_CORE_H
#define UST_CORE_H

#if defined(CONFIG_LTT) && defined(CONFIG_LTT_ALIGNMENT)

/*
 * Calculate the offset needed to align the type.
 * size_of_type must be non-zero.
 */
static inline unsigned int ltt_align(size_t align_drift, size_t size_of_type)
{
	size_t alignment = min(sizeof(void *), size_of_type);
	return (alignment - align_drift) & (alignment - 1);
}
/* Default arch alignment */
#define LTT_ALIGN

static inline int ltt_get_alignment(void)
{
	return sizeof(void *);
}

#else

static inline unsigned int ltt_align(size_t align_drift,
		 size_t size_of_type)
{
	return 0;
}

#define LTT_ALIGN __attribute__((packed))

static inline int ltt_get_alignment(void)
{
	return 0;
}
#endif /* defined(CONFIG_LTT) && defined(CONFIG_LTT_ALIGNMENT) */

#endif /* UST_CORE_H */
