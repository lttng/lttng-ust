#ifndef UST_TRACECTL_H
#define UST_TRACECTL_H

typedef struct ust_fork_info {
	sigset_t orig_sigs;
} ust_fork_info_t;

extern void ust_potential_exec(void);

extern void ust_before_fork(ust_fork_info_t *fork_info);
extern void ust_after_fork_parent(ust_fork_info_t *fork_info);
extern void ust_after_fork_child(ust_fork_info_t *fork_info);

#endif /* UST_TRACECTL_H */
