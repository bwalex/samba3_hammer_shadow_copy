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
    TAILQ_ENTRY(hammer_snapshot)	snap;
} *hammer_snapshot_t;

TAILQ_HEAD(hammer_snapshots_list, hammer_snapshot);
typedef struct hammer_snapshots {
    u_int32_t				count;
    TAILQ_HEAD(, hammer_snapshot)	snaps;
} *hammer_snapshots_t;

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

    syslog(LOG_CRIT, "HAMMER: hammer_match_gmt: %s", name);

    ret = strnstr(name, HAMMER_GMT_LABEL_PREFIX, strlen(name));
    if (ret == NULL)
        return (NULL);

    if (sscanf(ret, "@GMT-%04d.%02d.%02d-%02d.%02d.%02d",
        &year, &month, &day, &hour, &min, &sec) != 6)
    {
        syslog(LOG_CRIT, "HAMMER: sscanf GMT-foo ok");
        return (NULL);
    }

    if (tm != NULL) {
        syslog(LOG_CRIT, "HAMMER: tm != NULL: %d, %d, %d, %d, %d, %d", sec, min, hour, day, month, year);
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

    syslog(LOG_CRIT, "HAMMER: hammer_replace_gmt_tid: ent: %s", path);
    ret = talloc_size(talloc_tos(), strlen(path)+1);
    offset = hammer_match_gmt(path, NULL);
    if (offset != NULL) {
        syslog(LOG_CRIT, "HAMMER:  hammer_replace_gmt_tid: off != NULL: %s", offset);
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

    syslog(LOG_CRIT, "HAMMER: hammer_replace_gmt_tid: ret: %s", ret);

    return (ret);
}

static
char *
hammer_strip_gmt(const char *path)
{
    char *offset, *ret = NULL;

    syslog(LOG_CRIT, "HAMMER: hammer_strip_gmt: ent: %s", path);

    ret = talloc_strdup(talloc_tos(), path);
    offset = hammer_match_gmt(ret, NULL);
    if (offset != NULL) {
        syslog(LOG_CRIT, "HAMMER: hammer_strip_gmt: offset != NULL: %s", offset);
        if (strlen(offset) == HAMMER_GMT_LABEL_LENGTH) {
            syslog(LOG_CRIT, "HAMMER: hammer_strip_gmt: offset is 24 (pure GMT)");
            ret = ".";
            return (ret);
        }

        strncpy(offset, offset + (HAMMER_GMT_LABEL_LENGTH + 1),
                strlen(offset) - (HAMMER_GMT_LABEL_LENGTH + 1));
        offset[strlen(offset)-(HAMMER_GMT_LABEL_LENGTH + 1)] = '\0'; 
    }

    syslog(LOG_CRIT, "HAMMER: hammer_strip_gmt: ex: %s", ret);

    return (ret);
}

static
int
hammer_translate_gmt_to_tid(struct smb_filename *smb_fname)
{
    struct tm tm;
    time_t gm_time;
    hammer_snapshots_t snapshots;
    hammer_snapshot_t snapshot;
    char *s, *g, *cwd;

    g = hammer_match_gmt(smb_fname->base_name, &tm);
    if (g == NULL)
        return -1;

    syslog(LOG_CRIT, "HAMMER: hammer_stat: basename: %s", smb_fname->base_name);
    s = hammer_strip_gmt(smb_fname->base_name);
    syslog(LOG_CRIT, "HAMMER: hammer_stat: getting snapshots: %s", s);
    snapshots = hammer_get_snapshots(talloc_tos(), s);
    if (snapshots == NULL) {
        syslog(LOG_CRIT, "HAMMER: hammer_stat: no snapshots!");
        return -1;
    }

    gm_time = timegm(&tm);

    TAILQ_FOREACH(snapshot, &snapshots->snaps, snap) {
        time_t t = snapshot->ts / 1000000ULL;
        syslog(LOG_CRIT, "HAMMER: hammer_stat: (samba time) %d vs %d (snapshot time)", gm_time, t);
        if (t == gm_time) {
            syslog(LOG_CRIT, "HAMMER: hammer_stat: t == gm_time");
            smb_fname->base_name = hammer_replace_gmt_tid(smb_fname->base_name,
                                                          snapshot->tid);
            return 0;
        }
    }

    return -1;
}

static
int
hammer_fstat(vfs_handle_struct *handle, files_struct *fsp,
             SMB_STRUCT_STAT *sbuf)
{
    return (SMB_VFS_NEXT_FSTAT(handle, fsp, sbuf));
}

static
int
hammer_lstat(vfs_handle_struct *handle, struct smb_filename *smb_fname)
{
    hammer_translate_gmt_to_tid(smb_fname);
    return (SMB_VFS_NEXT_LSTAT(handle, smb_fname));
}

static
int
hammer_stat(vfs_handle_struct *handle, struct smb_filename *smb_fname)
{
    char *cwd;

    cwd = getcwd(NULL, MAXPATHLEN);
    syslog(LOG_CRIT, "HAMMER: hammer_stat, cwd is: %s", cwd);

    hammer_translate_gmt_to_tid(smb_fname);

    return (SMB_VFS_NEXT_STAT(handle, smb_fname));
}

static
int
hammer_open(vfs_handle_struct *handle, struct smb_filename *smb_fname,
            files_struct *fsp, int flags, mode_t mode)
{
    hammer_translate_gmt_to_tid(smb_fname);
    return (SMB_VFS_NEXT_OPEN(handle, smb_fname, fsp, flags, mode));
}

static
SMB_STRUCT_DIR *
hammer_opendir(vfs_handle_struct *handle, const char *path, const char *mask,
               uint32 attr)
{
    SMB_STRUCT_DIR *sd = SMB_VFS_NEXT_OPENDIR(handle, path, mask, attr);

syslog(LOG_CRIT, "HAMMER: hammer_opendir: path: %s, mask: %s", path, mask);

    while (1) {
        SMB_STRUCT_DIRENT *d;

        d = SMB_VFS_NEXT_READDIR(handle, sd, NULL);
        if (d == NULL)
            break;

// syslog(LOG_CRIT, "HAMMER: hammer_opendir, hide?: %s", d->d_name);
    }

    SMB_VFS_NEXT_REWINDDIR(handle, sd);
    return (sd);
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
