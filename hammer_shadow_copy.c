/*
 * HAMMER shadow copy implementation that utilizes the file system's native
 * snapshot support. This is based on the original shadow copy module from
 * 2004, the onefs shadow copy module and the new shadow copy2 module.
 *
 * Copyright (C) Samuel J. Greear      2011
 * Copyright (C) Alex Hornung          2011
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */
/*
 * The rough manner in which shadow copies work (at least from the perspective
 * of this module) is as follows. When you traverse to the "Previous Versions"
 * tab in the properties menu in the Windows Explorer shell, the
 * get_shadow_copy_data function in this module is invoked with the name of
 * the directory containing the file in question. After this module returns
 * a list of available "Volume labels" (snapshots), windows begins stat'ing
 * them in sequence using some combination of the path, the filename and the
 * @GMT formatted Volume label. For example,
 */
 // path/@GMT-*/to/file
 // @GMT-*/path/to.file
 // ./@GMT-*/file
/*
 * These are translated into absolute pathnames corresponding to snapshots
 * using the HAMMER TID format by this module. Windows looks at the stat
 * results of each valid return and lists all versions of the file which it
 * deems to be different based on the stat result.
 */

// XXX
#include <syslog.h>
#include <stdarg.h>
// XXX

#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include <sys/param.h>
#include <sys/queue.h>
#include <fs/hammer/hammer_disk.h>
#include <fs/hammer/hammer_ioctl.h>

#include "includes.h"

typedef struct hammer_snapshot {
    hammer_tid_t        tid;
    u_int64_t           ts;
    char                label[64];
    TAILQ_ENTRY(hammer_snapshot) snap;
} *hammer_snapshot_t;

TAILQ_HEAD(hammer_snapshots_list, hammer_snapshot);
typedef struct hammer_snapshots {
    u_int32_t                      count;
    TAILQ_HEAD(, hammer_snapshot)  snaps;
} *hammer_snapshots_t;


typedef struct hammer_history_entry {
    hammer_tid_t	tid;
    u_int32_t	time32;
    TAILQ_ENTRY(hammer_history_entry)  entry;
} *hammer_history_entry_t;

TAILQ_HEAD(hammer_history_list, hammer_history);
typedef struct hammer_history {
    u_int32_t	count;
    TAILQ_HEAD(, hammer_history_entry) hist;
} *hammer_history_t;


/*
 * Return a human-readable timestamp (XXX: remove later!)
 */
static const char *
timestr32(u_int32_t time32)
{
    static char timebuf[64];
    time_t t = (time_t)time32;
    struct tm *tp;

    tp = localtime(&t);
    strftime(timebuf, sizeof(timebuf), "%d-%b-%Y %H:%M:%S", tp);
    return(timebuf);
}

static
void
hammer_free_history(hammer_history_t hist)
{
    hammer_history_entry_t entry;

    if (hist == NULL)
        return;

    while ((entry = TAILQ_FIRST(&hist->hist)) != NULL) {
        --hist->count;
        TAILQ_REMOVE(&hist->hist, entry, entry);
        free(entry);
    }

    free(hist);
}

static
hammer_history_t
hammer_get_history(const char *path, off_t end_tid)
{
    struct hammer_ioc_history hist;
    hammer_history_t ret_history;
    const char *status;
    int fd;
    int i;

    //printf("%s\t", path);
    fd = open(path, O_RDONLY);
    if (fd < 0) {
        printf("%s\n", strerror(errno));
        return NULL;
    }
    bzero(&hist, sizeof(hist));
    hist.beg_tid = HAMMER_MIN_TID;
    hist.end_tid = end_tid; //HAMMER_MAX_TID;

    if (ioctl(fd, HAMMERIOC_GETHISTORY, &hist) < 0) {
        printf("%s\n", strerror(errno));
        close(fd);
        return NULL;
    }
    status = ((hist.head.flags & HAMMER_IOC_HISTORY_UNSYNCED) ?
        "dirty" : "clean");
    //printf("%016jx \t(count=%d) {\n", (uintmax_t)hist.obj_id, hist.count);

    ret_history = (hammer_history_t)malloc(sizeof(*ret_history));
    if (ret_history == NULL)
        return NULL;

    TAILQ_INIT(&ret_history->hist);
    ret_history->count = 0;

    for (;;) {
        for (i = 0; i < hist.count; ++i) {
            char *hist_path = NULL;
            hammer_history_entry_t ret_entry;

            ret_entry = (hammer_history_entry_t)malloc(sizeof(*ret_entry));
            if (ret_entry == NULL)
                goto fail;
            ret_entry->tid = hist.hist_ary[i].tid;
            ret_entry->time32 = hist.hist_ary[i].time32;
            ++ret_history->count;
            TAILQ_INSERT_HEAD(&ret_history->hist, ret_entry, entry);
        }
        if (hist.head.flags & HAMMER_IOC_HISTORY_EOF)
            break;
        if (hist.head.flags & HAMMER_IOC_HISTORY_NEXT_KEY)
            break;
        if ((hist.head.flags & HAMMER_IOC_HISTORY_NEXT_TID) == 0)
            break;
        hist.beg_tid = hist.nxt_tid;
        if (ioctl(fd, HAMMERIOC_GETHISTORY, &hist) < 0) {
            //printf("    error: %s\n", strerror(errno));
            break;
        }
    }
    //printf("}\n");
    close(fd);

    return ret_history;

fail:
    /* XXX deallocate */
    hammer_free_history(ret_history);
    return NULL;
}

static
void
hammer_free_snapshots(hammer_snapshots_t snapshots)
{
    (void)talloc_free(snapshots);
}

static
hammer_snapshots_t
hammer_get_snapshots(TALLOC_CTX *mem_ctx, char *path)
{
    struct hammer_ioc_pseudofs_rw ioc_pfs;
    struct hammer_pseudofs_data pfs_data;
    struct hammer_ioc_info ioc_info;
    struct hammer_ioc_snapshot ioc_snapshot;
    hammer_snapshots_t ret_snapshots;
    int i, fd;

    fd = open(path, O_RDONLY);
    if (fd < 0)
        goto fail;

    memset(&ioc_pfs, 0, sizeof(ioc_pfs));
    memset(&pfs_data, 0, sizeof(pfs_data));
    ioc_pfs.pfs_id = -1;
    ioc_pfs.ondisk = &pfs_data;
    ioc_pfs.bytes = sizeof(pfs_data);
    if (ioctl(fd, HAMMERIOC_GET_PSEUDOFS, &ioc_pfs) < 0)
        goto fail;

    memset(&ioc_info, 0, sizeof(ioc_info));
    if (ioctl(fd, HAMMERIOC_GET_INFO, &ioc_info) < 0)
        goto fail;

    ret_snapshots = (hammer_snapshots_t)
        talloc_size(mem_ctx, sizeof(*ret_snapshots));
    if (ret_snapshots == NULL)
        goto fail;

    ret_snapshots->count = 0;
    TAILQ_INIT(&ret_snapshots->snaps);

    memset(&ioc_snapshot, 0, sizeof(ioc_snapshot));
    do {
        if (ioctl(fd, HAMMERIOC_GET_SNAPSHOT, &ioc_snapshot) < 0)
            goto fail;

        for (i = 0; i < ioc_snapshot.count; ++i) {
            struct hammer_snapshot_data *snap = &ioc_snapshot.snaps[i];
            hammer_snapshot_t ret_snap;            

            ret_snap = (hammer_snapshot_t)
                talloc_size(ret_snapshots, sizeof(*ret_snap));
            if (ret_snap == NULL)
                goto fail;

            memcpy(&ret_snap->tid, &snap->tid, sizeof(ret_snap->tid));
            memcpy(&ret_snap->ts, &snap->ts, sizeof(ret_snap->ts));
            memcpy(&ret_snap->label, &snap->label, sizeof(*ret_snap->label));

            TAILQ_INSERT_HEAD(&ret_snapshots->snaps, ret_snap, snap);
            ++ret_snapshots->count;
        }
    } while (ioc_snapshot.head.error == 0 && ioc_snapshot.count > 0);

    return (ret_snapshots);

fail:
    close(fd);
    hammer_free_snapshots(ret_snapshots);
    return (NULL);
}

#define HAMMER_GMT_LABEL_PREFIX		"@GMT-"
#define HAMMER_GMT_LABEL_FORMAT		"@GMT-%Y.%m.%d-%H.%M.%S"
/* @GMT-2011.01.01-14.30.50" <- 24 bytes */
#define HAMMER_GMT_LABEL_LENGTH     24
#define HAMMER_TID_LABEL_LENGTH     20

static
char *
hammer_match_gmt(const char *name, struct tm *tm)
{
    int year, month, day, hour, min, sec;
    char *ret = NULL;

    ret = strnstr(name, HAMMER_GMT_LABEL_PREFIX, strlen(name));
    if (ret == NULL)
        return (NULL);

    if (sscanf(ret, "@GMT-%04d.%02d.%02d-%02d.%02d.%02d",
        &year, &month, &day, &hour, &min, &sec) != 6)
    {
        return (NULL);
    }

    if (tm != NULL) {
        memset(tm, 0, sizeof(struct tm));
        tm->tm_sec = sec;
        tm->tm_min = min;
        tm->tm_hour = hour;
        tm->tm_mday = day;
        tm->tm_mon = month - 1; /* in 0-11 format */
        tm->tm_year = year - 1900; /* years since 1900 */
    }
    return (ret);
}

static
char *
hammer_replace_gmt_tid(const char *path, hammer_tid_t tid)
{
    char *offset, *ptr, *ret = NULL;

    //syslog(LOG_CRIT, "HAMMER: hammer_replace_gmt_tid: ent: %s", path);
    ret = talloc_size(talloc_tos(), strlen(path)+1);
    offset = hammer_match_gmt(path, NULL);
    if (offset != NULL) {
        //syslog(LOG_CRIT, "HAMMER:  hammer_replace_gmt_tid: off != NULL: %s", offset);
        int i = strlen(offset); /* Path starting at GMT-* */
        int blen = path-offset; /* Length of path before GMT-* */
        ptr = ret;

        strncpy(ptr, offset, blen); /* Copy path before GMT-* */
        ptr += blen;

        snprintf(ptr, HAMMER_TID_LABEL_LENGTH+1, "@@0x%016jx",
                 (uintmax_t)tid);
        ptr += HAMMER_TID_LABEL_LENGTH;

        strncpy(ptr, offset + HAMMER_GMT_LABEL_LENGTH,
                i - HAMMER_GMT_LABEL_LENGTH + 1);
    }

    syslog(LOG_CRIT, "HAMMER: hammer_replace_gmt_tid: %s => %s", path, ret);

    return (ret);
}

static
char *
hammer_strip_gmt(const char *path)
{
    char *offset, *ret = NULL;

    //syslog(LOG_CRIT, "HAMMER: hammer_strip_gmt: ent: %s", path);

    ret = talloc_strdup(talloc_tos(), path);
    offset = hammer_match_gmt(ret, NULL);
    if (offset != NULL) {
        //syslog(LOG_CRIT, "HAMMER: hammer_strip_gmt: offset != NULL: %s", offset);
        if (strlen(offset) == HAMMER_GMT_LABEL_LENGTH) {
            //syslog(LOG_CRIT, "HAMMER: hammer_strip_gmt: offset is 24 (pure GMT)");
            ret = ".";
            return (ret);
        }

        strncpy(offset, offset + (HAMMER_GMT_LABEL_LENGTH + 1),
                strlen(offset) - (HAMMER_GMT_LABEL_LENGTH + 1));
        offset[strlen(offset)-(HAMMER_GMT_LABEL_LENGTH + 1)] = '\0';
    }

    syslog(LOG_CRIT, "HAMMER: hammer_strip_gmt: %s => %s", path, ret);

    return (ret);
}

static
char *
hammer_translate_gmt_to_tid(char *fname)
{
    struct tm tm;
    time_t gm_time;
    hammer_snapshots_t snapshots;
    hammer_snapshot_t snapshot;
    char *s, *g, *cwd;

    g = hammer_match_gmt(fname, &tm);
    if (g == NULL)
        return fname;

    //syslog(LOG_CRIT, "HAMMER: hammer_stat: basename: %s", fname);
    s = hammer_strip_gmt(fname);
    syslog(LOG_CRIT, "HAMMER: hammer_stat: getting snapshots: %s", s);
    snapshots = hammer_get_snapshots(talloc_tos(), s);
    if (snapshots == NULL) {
        syslog(LOG_CRIT, "HAMMER: hammer_stat: no snapshots!");
        return fname;
    }

    gm_time = timegm(&tm);

    TAILQ_FOREACH(snapshot, &snapshots->snaps, snap) {
        time_t t = snapshot->ts / 1000000ULL;
        //syslog(LOG_CRIT, "HAMMER: hammer_stat: (samba time) %d vs %d (snapshot time)", gm_time, t);
        if (t == gm_time) {
            //syslog(LOG_CRIT, "HAMMER: hammer_stat: t == gm_time");
            return hammer_replace_gmt_tid(fname, snapshot->tid);
        }
    }

    return fname;
}

#define SHADOW_NEXT(op, args, rtype) do {                             \
                char *cpath = NULL;                                   \
                rtype ret;                                            \
                cpath = hammer_translate_gmt_to_tid(path);            \
                syslog(LOG_CRIT, "HAMMER: samba vfs " #op " %s => %s", path, cpath); \
                ret = SMB_VFS_NEXT_ ## op args;                       \
                return ret;                                           \
        } while (0)

#define _SHADOW_NEXT_SMB_FNAME(op, args, rtype, err, fn) do {         \
                char *orig = smb_fname->base_name;                    \
                rtype ret;                                            \
                char *match = hammer_match_gmt(smb_fname->base_name, NULL); \
                smb_fname->base_name = hammer_translate_gmt_to_tid(smb_fname->base_name); \
                syslog(LOG_CRIT, "HAMMER: samba vfs " #op " %s => %s", orig, smb_fname->base_name); \
                ret = SMB_VFS_NEXT_ ## op args;                       \
                syslog(LOG_CRIT, "HAMMER: samba vfs " #op " match: %s, ret: %d", match, ret); \
                if (match != NULL && (ret != err)) {                  \
                    fn;                                               \
                }                                                     \
                return ret;                                           \
        } while (0)

#define SHADOW_NEXT_SMB_FNAME(op, args, rtype) do {                   \
                char *orig = smb_fname->base_name;                    \
                rtype ret;                                            \
                smb_fname->base_name = hammer_translate_gmt_to_tid(smb_fname->base_name); \
                syslog(LOG_CRIT, "HAMMER: samba vfs " #op " %s => %s", orig, smb_fname->base_name); \
                ret = SMB_VFS_NEXT_ ## op args;                       \
                return ret;                                           \
        } while (0)

/*
  modify a sbuf return to ensure that inodes in the shadow directory
  are different from those in the main directory
 */
static void convert_sbuf(vfs_handle_struct *handle, const char *fname, SMB_STRUCT_STAT *sbuf)
{
    hammer_history_t hist;
    hammer_history_entry_t entry;
    char *ptr;
    off_t tid;

    syslog(LOG_CRIT, "HAMMER samba convert_sbuf!!");

    ptr = strstr(fname, "@@0x");
    if (ptr == NULL)
        return;

    ptr+=2;
    tid = strtoll(ptr, NULL, 0);
    syslog(LOG_CRIT, "HAMMER samba convert_sbuf (ptr=%s, tid=%jx)", ptr, tid);
    hist = hammer_get_history(fname, tid);
    if (hist != NULL) {
        entry = TAILQ_FIRST(&hist->hist);
        syslog(LOG_CRIT, "HAMMER samba: Got best entry: %#jx (%s), now hacking mtime and atime\n", entry->tid, timestr32(entry->time32));
        sbuf->st_ex_atime.tv_sec = entry->time32;
        sbuf->st_ex_atime.tv_nsec = 0;
        sbuf->st_ex_mtime.tv_sec = entry->time32;
        sbuf->st_ex_mtime.tv_nsec = 0;
        hammer_free_history(hist);
    }
}

static
int
hammer_fstat(vfs_handle_struct *handle, files_struct *fsp,
             SMB_STRUCT_STAT *sbuf)
{
    int ret = SMB_VFS_NEXT_FSTAT(handle, fsp, sbuf);

    syslog(LOG_CRIT, "HAMMER: samba vfs FSTAT %s", fsp->fsp_name->base_name);
    if (ret == 0 && hammer_match_gmt(fsp->fsp_name->base_name, NULL))
        convert_sbuf(handle, fsp->fsp_name->base_name, sbuf);
    return ret;
}

static
int
hammer_lstat(vfs_handle_struct *handle, struct smb_filename *smb_fname)
{
    _SHADOW_NEXT_SMB_FNAME(LSTAT, (handle, smb_fname), int, -1,
        convert_sbuf(handle, smb_fname->base_name,
        &smb_fname->st));
}

static
int
hammer_stat(vfs_handle_struct *handle, struct smb_filename *smb_fname)
{
    _SHADOW_NEXT_SMB_FNAME(STAT, (handle, smb_fname), int, -1,
        convert_sbuf(handle, smb_fname->base_name,
        &smb_fname->st));
}

static
int
hammer_open(vfs_handle_struct *handle, struct smb_filename *smb_fname,
            files_struct *fsp, int flags, mode_t mode)
{
    SHADOW_NEXT_SMB_FNAME(OPEN, (handle, smb_fname, fsp, flags, mode), int);
}

static
SMB_STRUCT_DIR *
hammer_opendir(vfs_handle_struct *handle, const char *path, const char *mask,
               uint32 attr)
{
    SHADOW_NEXT(OPENDIR, (handle, cpath, mask, attr), SMB_STRUCT_DIR *);
}

static
int
hammer_statvfs(struct vfs_handle_struct *handle, const char *path,
               struct vfs_statvfs_struct *statbuf)
{
    SHADOW_NEXT(STATVFS, (handle, cpath, statbuf), int);
}

static
int
hammer_chdir(vfs_handle_struct *handle, const char *path)
{
    SHADOW_NEXT(CHDIR, (handle, cpath), int);
}

static
int
hammer_readlink(vfs_handle_struct *handle, const char *path,
                char *buf, size_t bufsiz)
{
    SHADOW_NEXT(READLINK, (handle, cpath, buf, bufsiz), int);
}

static
char *
hammer_realpath(vfs_handle_struct *handle, const char *path, char *resolved_path)
{
    SHADOW_NEXT(REALPATH, (handle, cpath, resolved_path), char *);
}

static
int
hammer_ntimes(vfs_handle_struct *handle,
              const struct smb_filename *smb_fname_in,
              struct smb_file_time *ft)
{
    struct smb_filename *smb_fname = NULL;
    NTSTATUS status;

    status = copy_smb_filename(talloc_tos(), smb_fname_in, &smb_fname);
    if (!NT_STATUS_IS_OK(status)) {
        errno = map_errno_from_nt_status(status);
        return -1;
    }

    SHADOW_NEXT_SMB_FNAME(NTIMES, (handle, smb_fname, ft), int);
}

static
int
hammer_get_shadow_copy_data(vfs_handle_struct *handle, files_struct *fsp,
                            SHADOW_COPY_DATA *shadow_copy_data, bool labels)
{
    int filled_labels = 0;
    int error = -1;
    hammer_snapshots_t snapshots;
    hammer_snapshot_t snapshot;

    shadow_copy_data->num_volumes = 0;
    shadow_copy_data->labels = NULL;

    snapshots = hammer_get_snapshots(shadow_copy_data->mem_ctx,
        fsp->conn->connectpath);
    if (snapshots == NULL) {
        return (error);
    }

    syslog(LOG_CRIT, "HAMMER: Got %d snapshots for file/dir", snapshots->count);
    shadow_copy_data->num_volumes = snapshots->count;
    error = 0;

    if (labels) {
    syslog(LOG_CRIT, "Filling labels");
        SHADOW_COPY_LABEL *rlabels = TALLOC_ZERO_ARRAY(shadow_copy_data->mem_ctx,
           SHADOW_COPY_LABEL, snapshots->count);
        if (rlabels == NULL)
            goto done;

        TAILQ_FOREACH(snapshot, &snapshots->snaps, snap) {

            time_t t = snapshot->ts / 1000000ULL;
            struct tm *tp = gmtime(&t);
            strftime(rlabels[filled_labels++], sizeof(*rlabels),
                HAMMER_GMT_LABEL_FORMAT, tp);

            syslog(LOG_CRIT, "HAMMER: Adding label: %s", rlabels[filled_labels-1]);
        }

        shadow_copy_data->labels = rlabels;
    }

    syslog(LOG_CRIT, "HAMMER: Filled %d labels", filled_labels);
    syslog(LOG_CRIT, "HAMMER: Found %d snapshots", shadow_copy_data->num_volumes);

done:
    hammer_free_snapshots(snapshots);
    return (error);
}


static struct vfs_fn_pointers hammer_shadow_copy_fns = {
    .fstat = hammer_fstat,
    .lstat = hammer_lstat,
    .stat = hammer_stat,
    .open = hammer_open,
    .opendir = hammer_opendir,
    .chdir = hammer_chdir,
    .statvfs = hammer_statvfs,
    .vfs_readlink = hammer_readlink,
    .realpath = hammer_realpath,
    .ntimes = hammer_ntimes,
    /* XXX: readdir? */
    .get_shadow_copy_data = hammer_get_shadow_copy_data
};

NTSTATUS init_samba_module(void)
{
    NTSTATUS ret = smb_register_vfs(SMB_VFS_INTERFACE_VERSION,
        "hammer_shadow_copy", &hammer_shadow_copy_fns);

    if (!NT_STATUS_IS_OK(ret))
        return (ret);

    syslog(LOG_CRIT, "HAMMER: init_samba_module");

    return (ret);
}
