/*
    This file is part of RIBS2.0 (Robust Infrastructure for Backend Systems).
    RIBS is an infrastructure for building great SaaS applications (but not
    limited to).

    Copyright (C) 2012,2013 Adap.tv, Inc.

    RIBS is free software: you can redistribute it and/or modify
    it under the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation, version 2.1 of the License.

    RIBS is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with RIBS.  If not, see <http://www.gnu.org/licenses/>.
*/
#include "file_mapper.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "logger.h"
#include "vm_misc.h"
#include <sys/mman.h>
#ifdef __APPLE__
#include "apple.h"
#endif

int file_mapper_init(struct file_mapper *fm, const char *filename) {
    return file_mapper_init2(fm, filename, 0, O_RDONLY | O_CLOEXEC, PROT_READ, MAP_SHARED);
}

int file_mapper_init2(struct file_mapper *fm, const char *filename, size_t size, int flags, int mmap_prot, int mmap_flags) {
    if (0 > file_mapper_free(fm))
        return -1;
    int fd = open(filename, flags);
    if (fd < 0)
        return LOGGER_PERROR_FUNC("open: %s", filename), -1;
    if (0 == size) {
        struct stat st;
        if (0 > fstat(fd, &st))
            return LOGGER_PERROR_FUNC("fstat: %s", filename), close(fd), -1;
        size = st.st_size;
    } else {
        if (0 > ftruncate(fd, size))
            return LOGGER_PERROR("ftruncate: %s", filename), close(fd), -1;
    }
    fm->size = size;
    fm->mem = size ? (char *)mmap(NULL, RIBS_VM_ALIGN(size), mmap_prot, mmap_flags, fd, 0) : NULL;
    close(fd);
    if (MAP_FAILED == fm->mem)
        return LOGGER_PERROR_FUNC("mmap %s", filename), fm->mem = NULL, -1;
    return 0;
}

int file_mapper_init_rw(struct file_mapper *fm, const char *filename, size_t size) {
    return file_mapper_init2(fm, filename, size, O_RDWR | O_CREAT | O_CLOEXEC, PROT_READ | PROT_WRITE, MAP_SHARED);
}

int file_mapper_free(struct file_mapper *fm) {
    if (NULL == fm->mem)
        return 0;
    int res;
    if (0 > (res = munmap(fm->mem, RIBS_VM_ALIGN(fm->size))))
        LOGGER_PERROR_FUNC("munmap");
    fm->mem = NULL;
    fm->size = 0;
    return res;
}
