#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/openat2.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

typedef struct napi_env__ *napi_env;
typedef struct napi_value__ *napi_value;
typedef struct napi_callback_info__ *napi_callback_info;
typedef napi_value (*napi_callback)(napi_env env, napi_callback_info info);

#define NAPI_AUTO_LENGTH ((size_t)-1)

extern int napi_create_function(napi_env env, const char *utf8name, size_t length,
    napi_callback cb, void *data, napi_value *result);
extern int napi_set_named_property(napi_env env, napi_value object, const char *utf8name,
    napi_value value);
extern int napi_get_cb_info(napi_env env, napi_callback_info info, size_t *argc,
    napi_value *argv, napi_value *this_arg, void **data);
extern int napi_get_value_int32(napi_env env, napi_value value, int32_t *result);
extern int napi_get_value_int64(napi_env env, napi_value value, int64_t *result);
extern int napi_get_value_string_utf8(napi_env env, napi_value value, char *buf,
    size_t bufsize, size_t *result);
extern int napi_create_int32(napi_env env, int32_t value, napi_value *result);
extern int napi_create_int64(napi_env env, int64_t value, napi_value *result);
extern int napi_create_uint32(napi_env env, uint32_t value, napi_value *result);
extern int napi_create_string_utf8(napi_env env, const char *str, size_t length,
    napi_value *result);
extern int napi_create_object(napi_env env, napi_value *result);
extern int napi_create_array(napi_env env, napi_value *result);
extern int napi_set_element(napi_env env, napi_value array, uint32_t index, napi_value value);
extern int napi_create_error(napi_env env, napi_value code, napi_value msg, napi_value *result);
extern int napi_throw(napi_env env, napi_value error);
extern int napi_get_undefined(napi_env env, napi_value *result);

static napi_value throw_errno(napi_env env, const char *op) {
  char buf[160];
  snprintf(buf, sizeof(buf), "%s: %s", op, strerror(errno));
  napi_value msg;
  napi_value err;
  napi_value code;
  napi_value errno_value;
  napi_create_string_utf8(env, buf, NAPI_AUTO_LENGTH, &msg);
  napi_create_error(env, NULL, msg, &err);
  napi_create_string_utf8(env, "ERRNO", NAPI_AUTO_LENGTH, &code);
  napi_set_named_property(env, err, "code", code);
  napi_create_int32(env, errno, &errno_value);
  napi_set_named_property(env, err, "errno", errno_value);
  napi_throw(env, err);
  return NULL;
}

static int read_i32(napi_env env, napi_value value, int32_t *out) {
  return napi_get_value_int32(env, value, out);
}

static int read_u64(napi_env env, napi_value value, uint64_t *out) {
  int64_t signed_value = 0;
  if (napi_get_value_int64(env, value, &signed_value) != 0 || signed_value < 0) {
    errno = EINVAL;
    return -1;
  }
  *out = (uint64_t)signed_value;
  return 0;
}

static int read_path(napi_env env, napi_value value, char *buf, size_t buf_size) {
  size_t written = 0;
  if (napi_get_value_string_utf8(env, value, buf, buf_size, &written) != 0) {
    errno = EINVAL;
    return -1;
  }
  if (written >= buf_size - 1) {
    errno = ENAMETOOLONG;
    return -1;
  }
  return 0;
}

static napi_value export_u32(napi_env env, napi_value object, const char *name, uint32_t value) {
  napi_value number;
  napi_create_uint32(env, value, &number);
  napi_set_named_property(env, object, name, number);
  return object;
}

static napi_value export_u64(napi_env env, napi_value object, const char *name, uint64_t value) {
  napi_value number;
  napi_create_int64(env, (int64_t)value, &number);
  napi_set_named_property(env, object, name, number);
  return object;
}

static napi_value bind_function(napi_env env, napi_value exports, const char *name, napi_callback cb) {
  napi_value fn;
  napi_create_function(env, name, NAPI_AUTO_LENGTH, cb, NULL, &fn);
  napi_set_named_property(env, exports, name, fn);
  return exports;
}

static napi_value openat2_fn(napi_env env, napi_callback_info info) {
  size_t argc = 5;
  napi_value argv[5];
  napi_get_cb_info(env, info, &argc, argv, NULL, NULL);
  if (argc < 5) {
    errno = EINVAL;
    return throw_errno(env, "openat2");
  }
  int32_t dirfd = 0;
  uint64_t flags = 0;
  uint64_t mode = 0;
  uint64_t resolve = 0;
  char path[4096];
  if (read_i32(env, argv[0], &dirfd) != 0 || read_path(env, argv[1], path, sizeof(path)) != 0 ||
      read_u64(env, argv[2], &flags) != 0 || read_u64(env, argv[3], &mode) != 0 ||
      read_u64(env, argv[4], &resolve) != 0) {
    return throw_errno(env, "openat2");
  }
  struct open_how how = {
      .flags = flags,
      .mode = mode,
      .resolve = resolve,
  };
  long fd;
  do {
    fd = syscall(SYS_openat2, dirfd, path, &how, sizeof(how));
  } while (fd < 0 && errno == EINTR);
  if (fd < 0) return throw_errno(env, "openat2");
  napi_value result;
  napi_create_int32(env, (int32_t)fd, &result);
  return result;
}

static napi_value statx_fn(napi_env env, napi_callback_info info) {
  size_t argc = 4;
  napi_value argv[4];
  napi_get_cb_info(env, info, &argc, argv, NULL, NULL);
  if (argc < 4) {
    errno = EINVAL;
    return throw_errno(env, "statx");
  }
  int32_t dirfd = 0;
  int32_t flags = 0;
  uint64_t mask = 0;
  char path[4096];
  if (read_i32(env, argv[0], &dirfd) != 0 || read_path(env, argv[1], path, sizeof(path)) != 0 ||
      read_i32(env, argv[2], &flags) != 0 || read_u64(env, argv[3], &mask) != 0) {
    return throw_errno(env, "statx");
  }
  struct statx stx;
  memset(&stx, 0, sizeof(stx));
  int rc;
  do {
    rc = statx(dirfd, path, flags, (unsigned int)mask, &stx);
  } while (rc != 0 && errno == EINTR);
  if (rc != 0) return throw_errno(env, "statx");
  napi_value result;
  napi_create_object(env, &result);
  export_u32(env, result, "mask", stx.stx_mask);
  export_u32(env, result, "mode", stx.stx_mode);
  export_u32(env, result, "nlink", stx.stx_nlink);
  napi_value ino;
  char ino_buf[32];
  snprintf(ino_buf, sizeof(ino_buf), "%llu", (unsigned long long)stx.stx_ino);
  napi_create_string_utf8(env, ino_buf, NAPI_AUTO_LENGTH, &ino);
  napi_set_named_property(env, result, "ino", ino);
  export_u32(env, result, "devMajor", stx.stx_dev_major);
  export_u32(env, result, "devMinor", stx.stx_dev_minor);
  napi_value btime_sec;
  char btime_buf[32];
  snprintf(btime_buf, sizeof(btime_buf), "%lld", (long long)stx.stx_btime.tv_sec);
  napi_create_string_utf8(env, btime_buf, NAPI_AUTO_LENGTH, &btime_sec);
  napi_set_named_property(env, result, "btimeSec", btime_sec);
  export_u32(env, result, "btimeNsec", stx.stx_btime.tv_nsec);
  napi_value size;
  char size_buf[32];
  snprintf(size_buf, sizeof(size_buf), "%llu", (unsigned long long)stx.stx_size);
  napi_create_string_utf8(env, size_buf, NAPI_AUTO_LENGTH, &size);
  napi_set_named_property(env, result, "size", size);
  return result;
}

static napi_value close_fn(napi_env env, napi_callback_info info) {
  size_t argc = 1;
  napi_value argv[1];
  napi_get_cb_info(env, info, &argc, argv, NULL, NULL);
  int32_t fd = 0;
  if (argc < 1 || read_i32(env, argv[0], &fd) != 0) {
    errno = EINVAL;
    return throw_errno(env, "close");
  }
  if (close(fd) != 0) return throw_errno(env, "close");
  napi_value result;
  napi_get_undefined(env, &result);
  return result;
}

static napi_value unlinkat_fn(napi_env env, napi_callback_info info) {
  size_t argc = 3;
  napi_value argv[3];
  napi_get_cb_info(env, info, &argc, argv, NULL, NULL);
  int32_t dirfd = 0;
  int32_t flags = 0;
  char path[4096];
  if (argc < 3 || read_i32(env, argv[0], &dirfd) != 0 ||
      read_path(env, argv[1], path, sizeof(path)) != 0 || read_i32(env, argv[2], &flags) != 0) {
    errno = EINVAL;
    return throw_errno(env, "unlinkat");
  }
  int rc;
  do {
    rc = unlinkat(dirfd, path, flags);
  } while (rc != 0 && errno == EINTR);
  if (rc != 0) return throw_errno(env, "unlinkat");
  napi_value result;
  napi_get_undefined(env, &result);
  return result;
}

static napi_value renameat2_fn(napi_env env, napi_callback_info info) {
  size_t argc = 5;
  napi_value argv[5];
  napi_get_cb_info(env, info, &argc, argv, NULL, NULL);
  int32_t olddirfd = 0;
  int32_t newdirfd = 0;
  uint64_t flags = 0;
  char oldpath[4096];
  char newpath[4096];
  if (argc < 5 || read_i32(env, argv[0], &olddirfd) != 0 ||
      read_path(env, argv[1], oldpath, sizeof(oldpath)) != 0 ||
      read_i32(env, argv[2], &newdirfd) != 0 ||
      read_path(env, argv[3], newpath, sizeof(newpath)) != 0 ||
      read_u64(env, argv[4], &flags) != 0) {
    errno = EINVAL;
    return throw_errno(env, "renameat2");
  }
  int rc;
  do {
    rc = renameat2(olddirfd, oldpath, newdirfd, newpath, (unsigned int)flags);
  } while (rc != 0 && errno == EINTR);
  if (rc != 0) return throw_errno(env, "renameat2");
  napi_value result;
  napi_get_undefined(env, &result);
  return result;
}

static napi_value linkat_fn(napi_env env, napi_callback_info info) {
  size_t argc = 5;
  napi_value argv[5];
  napi_get_cb_info(env, info, &argc, argv, NULL, NULL);
  int32_t olddirfd = 0;
  int32_t newdirfd = 0;
  int32_t flags = 0;
  char oldpath[4096];
  char newpath[4096];
  if (argc < 5 || read_i32(env, argv[0], &olddirfd) != 0 ||
      read_path(env, argv[1], oldpath, sizeof(oldpath)) != 0 ||
      read_i32(env, argv[2], &newdirfd) != 0 ||
      read_path(env, argv[3], newpath, sizeof(newpath)) != 0 ||
      read_i32(env, argv[4], &flags) != 0) {
    errno = EINVAL;
    return throw_errno(env, "linkat");
  }
  int rc;
  do {
    rc = linkat(olddirfd, oldpath, newdirfd, newpath, flags);
  } while (rc != 0 && errno == EINTR);
  if (rc != 0) return throw_errno(env, "linkat");
  napi_value result;
  napi_get_undefined(env, &result);
  return result;
}

static napi_value listat_fn(napi_env env, napi_callback_info info) {
  size_t argc = 1;
  napi_value argv[1];
  napi_get_cb_info(env, info, &argc, argv, NULL, NULL);
  int32_t dirfd = 0;
  if (argc < 1 || read_i32(env, argv[0], &dirfd) != 0) {
    errno = EINVAL;
    return throw_errno(env, "listat");
  }
  int dupfd = dup(dirfd);
  if (dupfd < 0) return throw_errno(env, "listat");
  DIR *dir = fdopendir(dupfd);
  if (dir == NULL) {
    int saved = errno;
    close(dupfd);
    errno = saved;
    return throw_errno(env, "listat");
  }
  napi_value result;
  napi_create_array(env, &result);
  uint32_t index = 0;
  struct dirent *entry;
  errno = 0;
  while ((entry = readdir(dir)) != NULL) {
    if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) continue;
    napi_value name;
    napi_create_string_utf8(env, entry->d_name, NAPI_AUTO_LENGTH, &name);
    napi_set_element(env, result, index++, name);
  }
  int saved = errno;
  closedir(dir);
  if (saved != 0) {
    errno = saved;
    return throw_errno(env, "listat");
  }
  return result;
}

napi_value napi_register_module_v1(napi_env env, napi_value exports) {
  bind_function(env, exports, "openat2", openat2_fn);
  bind_function(env, exports, "statx", statx_fn);
  bind_function(env, exports, "close", close_fn);
  bind_function(env, exports, "unlinkat", unlinkat_fn);
  bind_function(env, exports, "renameat2", renameat2_fn);
  bind_function(env, exports, "linkat", linkat_fn);
  bind_function(env, exports, "listat", listat_fn);

  napi_value constants;
  napi_create_object(env, &constants);
  export_u64(env, constants, "O_RDONLY", (uint64_t)O_RDONLY);
  export_u64(env, constants, "O_WRONLY", (uint64_t)O_WRONLY);
  export_u64(env, constants, "O_RDWR", (uint64_t)O_RDWR);
  export_u64(env, constants, "O_CREAT", (uint64_t)O_CREAT);
  export_u64(env, constants, "O_EXCL", (uint64_t)O_EXCL);
  export_u64(env, constants, "O_TRUNC", (uint64_t)O_TRUNC);
  export_u64(env, constants, "O_DIRECTORY", (uint64_t)O_DIRECTORY);
  export_u64(env, constants, "O_NOFOLLOW", (uint64_t)O_NOFOLLOW);
  export_u64(env, constants, "O_CLOEXEC", (uint64_t)O_CLOEXEC);
  export_u64(env, constants, "O_PATH", (uint64_t)O_PATH);
  export_u64(env, constants, "O_NONBLOCK", (uint64_t)O_NONBLOCK);
  export_u64(env, constants, "RESOLVE_NO_XDEV", (uint64_t)RESOLVE_NO_XDEV);
  export_u64(env, constants, "RESOLVE_NO_MAGICLINKS", (uint64_t)RESOLVE_NO_MAGICLINKS);
  export_u64(env, constants, "RESOLVE_NO_SYMLINKS", (uint64_t)RESOLVE_NO_SYMLINKS);
  export_u64(env, constants, "RESOLVE_BENEATH", (uint64_t)RESOLVE_BENEATH);
  export_u64(env, constants, "RESOLVE_IN_ROOT", (uint64_t)RESOLVE_IN_ROOT);
  napi_value at_fdcwd;
  napi_create_int32(env, AT_FDCWD, &at_fdcwd);
  napi_set_named_property(env, constants, "AT_FDCWD", at_fdcwd);
  export_u32(env, constants, "AT_EMPTY_PATH", (uint32_t)AT_EMPTY_PATH);
  export_u32(env, constants, "AT_SYMLINK_NOFOLLOW", (uint32_t)AT_SYMLINK_NOFOLLOW);
  export_u32(env, constants, "AT_REMOVEDIR", (uint32_t)AT_REMOVEDIR);
  export_u32(env, constants, "STATX_TYPE", (uint32_t)STATX_TYPE);
  export_u32(env, constants, "STATX_MODE", (uint32_t)STATX_MODE);
  export_u32(env, constants, "STATX_NLINK", (uint32_t)STATX_NLINK);
  export_u32(env, constants, "STATX_INO", (uint32_t)STATX_INO);
  export_u32(env, constants, "STATX_SIZE", (uint32_t)STATX_SIZE);
  export_u32(env, constants, "STATX_BTIME", (uint32_t)STATX_BTIME);
  export_u32(env, constants, "S_IFMT", (uint32_t)S_IFMT);
  export_u32(env, constants, "S_IFREG", (uint32_t)S_IFREG);
  export_u32(env, constants, "S_IFDIR", (uint32_t)S_IFDIR);
  export_u32(env, constants, "S_IFLNK", (uint32_t)S_IFLNK);
  napi_set_named_property(env, exports, "constants", constants);
  return exports;
}
