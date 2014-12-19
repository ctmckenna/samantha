static inline void vmallocator_reset(struct vmallocator *v) {
    v->wlocpos = 0;
}

static inline size_t vmallocator_wlocpos(struct vmallocator *v) {
    return v->wlocpos;
}

static inline size_t vmallocator_avail(struct vmallocator *v) {
    return v->capacity - v->wlocpos;
}

static inline int vmallocator_check_resize(struct vmallocator *v, size_t s) {
    if (vmallocator_avail(v) < s) {
        size_t new_capacity = v->capacity;
        if (0 == new_capacity)
            return -1;
        do {
            new_capacity <<= 1;
        } while (new_capacity - v->wlocpos < s);
        return v->resize_func(v, new_capacity);
    }
    return 0;
}

static inline size_t vmallocator_alloc(struct vmallocator *v, size_t s) {
    if (0 > vmallocator_check_resize(v, s))
        return -1;
    size_t ofs = v->wlocpos;
    v->wlocpos += s;
    return ofs;
}

static inline size_t vmallocator_alloczero(struct vmallocator *v, size_t s) {
    size_t ofs = vmallocator_alloc(v, s);
    memset(vmallocator_ofs2mem(v, ofs), 0, s);
    return ofs;
}

static inline size_t vmallocator_alloczero_aligned(struct vmallocator *v, size_t s) {
    size_t ofs = vmallocator_alloc_aligned(v, s);
    memset(vmallocator_ofs2mem(v, ofs), 0, s);
    return ofs;
}

static inline size_t vmallocator_alloc_aligned(struct vmallocator *v, size_t s) {
    v->wlocpos = VM_ALLOC_ALIGN(v->wlocpos, VM_OFS_ALIGN_BYTES);
    if (0 > vmallocator_check_resize(v, s))
        return -1;
    size_t ofs = v->wlocpos;
    v->wlocpos += s;
    return ofs;
}

static inline void *vmallocator_allocptr(struct vmallocator *v, size_t s) {
    return vmallocator_ofs2mem(v, vmallocator_alloc(v, s));
}

static inline void *vmallocator_allocptr_aligned(struct vmallocator *v, size_t s) {
    return vmallocator_ofs2mem(v, vmallocator_alloc_aligned(v, s));
}

static inline void *vmallocator_ofs2mem(struct vmallocator *v, size_t ofs) {
    return v->mem + ofs;
}

