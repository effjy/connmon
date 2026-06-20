/*
 * Connection Monitor (connmon) - a real-time TCP connection monitor for Linux.
 *
 * A GTK3 desktop application that reads /proc/net/tcp and /proc/net/tcp6
 * (the same data netstat/ss use) and refreshes a live table of every TCP
 * connection on the system, decorated with a "cyber" dark theme.
 *
 * The PROCESS column is resolved by scanning /proc/<pid>/fd for the socket
 * inode of each connection. Sockets owned by other users only resolve when
 * run as root (otherwise they show "-"); launch via pkexec/sudo to see all.
 *
 * Author: Jean-Francois Lachance-Caumartin
 * Repository: https://github.com/effjy/connmon/
 */

#define _DEFAULT_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <ctype.h>
#include <dirent.h>
#include <arpa/inet.h>
#include <gtk/gtk.h>

#define APP_ID      "com.github.effjy.connmon"
#define APP_NAME    "Connection Monitor"
#define APP_VERSION "2.0"
#define APP_REPO    "https://github.com/effjy/connmon/"

/* ------------------------------------------------------------------ */
/* Backend: /proc parsing (ported from the original terminal version)  */
/* ------------------------------------------------------------------ */

/*
 * Map of socket inode -> owning process ("name/pid"), rebuilt on every
 * refresh by walking /proc. A hash table keeps lookups O(1), which matters
 * on busy hosts with thousands of sockets and file descriptors.
 *
 * The inode is used directly as the key (GSIZE_TO_POINTER); socket inodes
 * comfortably fit in a pointer on any realistic system.
 */
static GHashTable *proc_map = NULL; /* inode -> g_strdup'd "name/pid" */

static void proc_map_add(unsigned long inode, int pid, const char *name)
{
    if (inode == 0)
        return; /* no real socket has inode 0; avoids bogus matches */

    gpointer key = GSIZE_TO_POINTER(inode);
    /* First owner wins: deterministic attribution for sockets shared
     * across processes (fork/dup) regardless of /proc iteration order. */
    if (g_hash_table_contains(proc_map, key))
        return;
    g_hash_table_insert(proc_map, key, g_strdup_printf("%s/%d", name, pid));
}

/* Read the command name for a pid from /proc/<pid>/comm. */
static void read_comm(int pid, char *out, size_t outlen)
{
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/comm", pid);
    FILE *f = fopen(path, "r");
    if (!f) {
        snprintf(out, outlen, "?");
        return;
    }
    if (fgets(out, outlen, f)) {
        out[strcspn(out, "\n")] = '\0';
    } else {
        snprintf(out, outlen, "?");
    }
    fclose(f);
}

/* Walk /proc/<pid>/fd, recording the inode of every socket: link. */
static void build_proc_map(void)
{
    if (!proc_map)
        proc_map = g_hash_table_new_full(g_direct_hash, g_direct_equal,
                                         NULL, g_free);
    else
        g_hash_table_remove_all(proc_map); /* drop last scan's entries */

    DIR *proc = opendir("/proc");
    if (!proc)
        return;

    struct dirent *de;
    while ((de = readdir(proc)) != NULL) {
        if (!isdigit((unsigned char)de->d_name[0]))
            continue;
        int pid = atoi(de->d_name);

        char fdpath[64];
        snprintf(fdpath, sizeof(fdpath), "/proc/%d/fd", pid);
        DIR *fd = opendir(fdpath);
        if (!fd)
            continue; /* likely another user's process without root */

        char comm[64] = "";
        int got_comm = 0;

        struct dirent *fe;
        while ((fe = readdir(fd)) != NULL) {
            char link[320], target[128];
            snprintf(link, sizeof(link), "/proc/%d/fd/%s", pid, fe->d_name);
            ssize_t n = readlink(link, target, sizeof(target) - 1);
            if (n < 0)
                continue;
            target[n] = '\0';

            /* Socket links look like "socket:[12345]". */
            unsigned long inode;
            if (sscanf(target, "socket:[%lu]", &inode) == 1) {
                if (!got_comm) {
                    read_comm(pid, comm, sizeof(comm));
                    got_comm = 1;
                }
                proc_map_add(inode, pid, comm);
            }
        }
        closedir(fd);
    }
    closedir(proc);
}

/* Format "name/pid" for a socket inode, or "-" if unknown. */
static void resolve_proc(unsigned long inode, char *out, size_t outlen)
{
    const char *p = proc_map
        ? g_hash_table_lookup(proc_map, GSIZE_TO_POINTER(inode))
        : NULL;
    snprintf(out, outlen, "%s", p ? p : "-");
}

/* TCP states as exposed by the kernel in /proc/net/tcp (hex). */
static const char *tcp_state_name(unsigned int st)
{
    static const char *names[] = {
        "UNKNOWN",    "ESTABLISHED", "SYN_SENT",  "SYN_RECV",
        "FIN_WAIT1",  "FIN_WAIT2",   "TIME_WAIT", "CLOSE",
        "CLOSE_WAIT", "LAST_ACK",    "LISTEN",    "CLOSING",
        "NEW_SYN_RECV"
    };
    if (st < sizeof(names) / sizeof(names[0]))
        return names[st];
    return "?";
}

/*
 * /proc/net/tcp prints the address with "%08X" over the in-kernel __be32,
 * read as a host-order integer. The local kernel and this process share an
 * endianness, so parsing the hex back into a host integer and reusing its
 * raw bytes as s_addr reproduces the original network-order address on both
 * little- and big-endian machines. Format an "addr:port" string into out.
 */
static void fmt_ipv4(const char *hex_addr, unsigned int port, char *out, size_t outlen)
{
    unsigned int a;
    struct in_addr in;

    if (sscanf(hex_addr, "%x", &a) != 1) {
        snprintf(out, outlen, "?:%u", port);
        return;
    }
    in.s_addr = a;
    snprintf(out, outlen, "%s:%u", inet_ntoa(in), port);
}

/* IPv6 addresses are four host-order hex words (see fmt_ipv4 on endianness). */
static void fmt_ipv6(const char *hex_addr, unsigned int port, char *out, size_t outlen)
{
    unsigned int w[4];
    struct in6_addr in6;
    char buf[INET6_ADDRSTRLEN];

    if (sscanf(hex_addr, "%8x%8x%8x%8x", &w[0], &w[1], &w[2], &w[3]) != 4) {
        snprintf(out, outlen, "?:%u", port);
        return;
    }
    memcpy(&in6, w, sizeof(in6));
    inet_ntop(AF_INET6, &in6, buf, sizeof(buf));
    snprintf(out, outlen, "[%s]:%u", buf, port);
}

/* ------------------------------------------------------------------ */
/* GTK front-end                                                       */
/* ------------------------------------------------------------------ */

enum {
    COL_PROTO,
    COL_LOCAL,
    COL_REMOTE,
    COL_STATE,
    COL_UID,
    COL_PROCESS,
    N_COLS
};

typedef struct {
    GtkWidget    *window;
    GtkListStore *store;
    GtkWidget    *status_label;
    GtkWidget    *count_label;
    GtkWidget    *pause_btn;
    GtkSpinButton *interval_spin;
    guint         timer_id;
    gboolean      paused;
} App;

/* Parse one /proc/net/tcp{,6} file into the list store. Returns rows added. */
static int load_file(GtkListStore *store, const char *path, int is_v6)
{
    FILE *f = fopen(path, "r");
    if (!f)
        return 0; /* e.g. no IPv6 on this host */

    char line[512];
    int rows = 0;

    /* Skip the header line. */
    if (!fgets(line, sizeof(line), f)) {
        fclose(f);
        return 0;
    }

    while (fgets(line, sizeof(line), f)) {
        char local_hex[64], rem_hex[64];
        unsigned int local_port, rem_port, state;
        unsigned long inode = 0;
        unsigned int uid = 0;

        int n = sscanf(line,
            "%*d: %63[0-9A-Fa-f]:%x %63[0-9A-Fa-f]:%x %x %*x:%*x %*x:%*x %*x %u %*d %lu",
            local_hex, &local_port, rem_hex, &rem_port, &state, &uid, &inode);
        if (n < 5)
            continue;

        char local[80], remote[80];
        if (is_v6) {
            fmt_ipv6(local_hex, local_port, local, sizeof(local));
            fmt_ipv6(rem_hex, rem_port, remote, sizeof(remote));
        } else {
            fmt_ipv4(local_hex, local_port, local, sizeof(local));
            fmt_ipv4(rem_hex, rem_port, remote, sizeof(remote));
        }

        char proc[80];
        resolve_proc(inode, proc, sizeof(proc));

        GtkTreeIter iter;
        gtk_list_store_append(store, &iter);
        gtk_list_store_set(store, &iter,
            COL_PROTO,   is_v6 ? "tcp6" : "tcp",
            COL_LOCAL,   local,
            COL_REMOTE,  remote,
            COL_STATE,   tcp_state_name(state),
            COL_UID,     uid,
            COL_PROCESS, proc,
            -1);
        rows++;
    }

    fclose(f);
    return rows;
}

/* Rebuild the table from /proc. */
static void refresh(App *app)
{
    gtk_list_store_clear(app->store);
    build_proc_map();

    int rows = 0;
    rows += load_file(app->store, "/proc/net/tcp", 0);
    rows += load_file(app->store, "/proc/net/tcp6", 1);

    time_t now = time(NULL);
    char ts[64];
    strftime(ts, sizeof(ts), "%Y-%m-%d  %H:%M:%S", localtime(&now));

    char count[64];
    snprintf(count, sizeof(count), "%d connection%s", rows, rows == 1 ? "" : "s");
    gtk_label_set_text(GTK_LABEL(app->count_label), count);

    char status[128];
    snprintf(status, sizeof(status), "Last scan: %s%s", ts,
             geteuid() == 0 ? "  \xe2\x80\xa2  root" : "");
    gtk_label_set_text(GTK_LABEL(app->status_label), status);
}

static gboolean on_tick(gpointer data)
{
    App *app = data;
    if (!app->paused)
        refresh(app);
    return G_SOURCE_CONTINUE;
}

static void restart_timer(App *app)
{
    if (app->timer_id)
        g_source_remove(app->timer_id);
    int secs = gtk_spin_button_get_value_as_int(app->interval_spin);
    if (secs < 1)
        secs = 1;
    app->timer_id = g_timeout_add_seconds(secs, on_tick, app);
}

static void on_interval_changed(GtkSpinButton *spin, gpointer data)
{
    (void)spin;
    restart_timer((App *)data);
}

static void on_refresh_clicked(GtkButton *btn, gpointer data)
{
    (void)btn;
    refresh((App *)data);
}

static void on_pause_toggled(GtkToggleButton *btn, gpointer data)
{
    App *app = data;
    app->paused = gtk_toggle_button_get_active(btn);
    gtk_button_set_label(GTK_BUTTON(btn), app->paused ? "Resume" : "Pause");
    if (!app->paused)
        refresh(app);
}

/* Write the current table contents to a plain-text file. */
static void save_connections(App *app, const char *path)
{
    FILE *f = fopen(path, "w");
    if (!f) {
        GtkWidget *err = gtk_message_dialog_new(GTK_WINDOW(app->window),
            GTK_DIALOG_MODAL, GTK_MESSAGE_ERROR, GTK_BUTTONS_OK,
            "Could not write to %s", path);
        gtk_dialog_run(GTK_DIALOG(err));
        gtk_widget_destroy(err);
        return;
    }

    time_t now = time(NULL);
    char ts[64];
    strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", localtime(&now));
    fprintf(f, "# %s connection list - %s\n", APP_NAME, ts);
    fprintf(f, "%-6s  %-40s  %-40s  %-12s  %-6s  %s\n",
            "PROTO", "LOCAL", "REMOTE", "STATE", "UID", "PROCESS");

    GtkTreeModel *model = GTK_TREE_MODEL(app->store);
    GtkTreeIter iter;
    gboolean valid = gtk_tree_model_get_iter_first(model, &iter);
    while (valid) {
        gchar *proto, *local, *remote, *state, *proc;
        guint uid;
        gtk_tree_model_get(model, &iter,
            COL_PROTO,   &proto,
            COL_LOCAL,   &local,
            COL_REMOTE,  &remote,
            COL_STATE,   &state,
            COL_UID,     &uid,
            COL_PROCESS, &proc,
            -1);
        fprintf(f, "%-6s  %-40s  %-40s  %-12s  %-6u  %s\n",
                proto, local, remote, state, uid, proc);
        g_free(proto);
        g_free(local);
        g_free(remote);
        g_free(state);
        g_free(proc);
        valid = gtk_tree_model_iter_next(model, &iter);
    }

    fclose(f);
}

static void on_save_clicked(GtkButton *btn, gpointer data)
{
    App *app = data;
    (void)btn;

    GtkWidget *dialog = gtk_file_chooser_dialog_new("Save Connections",
        GTK_WINDOW(app->window), GTK_FILE_CHOOSER_ACTION_SAVE,
        "_Cancel", GTK_RESPONSE_CANCEL,
        "_Save",   GTK_RESPONSE_ACCEPT,
        NULL);
    GtkFileChooser *chooser = GTK_FILE_CHOOSER(dialog);
    gtk_file_chooser_set_do_overwrite_confirmation(chooser, TRUE);
    gtk_file_chooser_set_current_name(chooser, "connections.txt");

    if (gtk_dialog_run(GTK_DIALOG(dialog)) == GTK_RESPONSE_ACCEPT) {
        char *filename = gtk_file_chooser_get_filename(chooser);
        save_connections(app, filename);
        g_free(filename);
    }
    gtk_widget_destroy(dialog);
}

static void on_about_clicked(GtkButton *btn, gpointer data)
{
    App *app = data;
    (void)btn;

    GtkAboutDialog *about = GTK_ABOUT_DIALOG(gtk_about_dialog_new());
    gtk_window_set_transient_for(GTK_WINDOW(about), GTK_WINDOW(app->window));
    gtk_window_set_modal(GTK_WINDOW(about), TRUE);

    gtk_about_dialog_set_program_name(about, APP_NAME);
    gtk_about_dialog_set_version(about, APP_VERSION);
    gtk_about_dialog_set_comments(about,
        "A real-time TCP connection monitor for Linux.\n"
        "Reads /proc/net/tcp and resolves the owning process of each socket.");
    gtk_about_dialog_set_website(about, APP_REPO);
    gtk_about_dialog_set_website_label(about, "Repository");
    gtk_about_dialog_set_logo_icon_name(about, "connmon");
    gtk_about_dialog_set_copyright(about,
        "\xc2\xa9 2026 Jean-Francois Lachance-Caumartin");

    const char *authors[] = { "Jean-Francois Lachance-Caumartin", NULL };
    gtk_about_dialog_set_authors(about, authors);

    gtk_dialog_run(GTK_DIALOG(about));
    gtk_widget_destroy(GTK_WIDGET(about));
}

/* Cyber dark theme. */
static const char *CSS =
    "window { background-color: #0a0e14; }"
    ".cyber-header { background: linear-gradient(90deg, #0a0e14, #0d1b2a);"
    "  border-bottom: 1px solid #00e5ff; padding: 6px 10px; }"
    ".cyber-title { color: #00e5ff; font-family: monospace; font-weight: bold;"
    "  font-size: 16px; text-shadow: 0 0 6px #00e5ff; }"
    ".cyber-sub { color: #39ff14; font-family: monospace; font-size: 11px; }"
    "button { background: #11202e; color: #00e5ff; border: 1px solid #00e5ff;"
    "  border-radius: 4px; padding: 4px 12px; font-family: monospace; }"
    "button:hover { background: #00e5ff; color: #0a0e14; }"
    "button:checked { background: #ff2e63; border-color: #ff2e63; color: #0a0e14; }"
    "spinbutton, spinbutton entry { background: #11202e; color: #39ff14;"
    "  border: 1px solid #00e5ff; font-family: monospace; }"
    "treeview { background-color: #0a0e14; color: #c8f5ff; font-family: monospace;"
    "  font-size: 12px; }"
    "treeview:selected { background-color: #00e5ff; color: #0a0e14; }"
    "treeview header button { background: #0d1b2a; color: #39ff14;"
    "  border: 0; border-bottom: 1px solid #00e5ff; border-radius: 0;"
    "  font-weight: bold; text-shadow: 0 0 4px #39ff14; }"
    ".status-bar { background: #0d1b2a; border-top: 1px solid #00e5ff;"
    "  padding: 4px 10px; }"
    ".status-text { color: #6fa8b8; font-family: monospace; font-size: 11px; }"
    ".count-text { color: #39ff14; font-family: monospace; font-weight: bold;"
    "  font-size: 11px; }";

static void apply_css(void)
{
    GtkCssProvider *provider = gtk_css_provider_new();
    gtk_css_provider_load_from_data(provider, CSS, -1, NULL);
    gtk_style_context_add_provider_for_screen(
        gdk_screen_get_default(),
        GTK_STYLE_PROVIDER(provider),
        GTK_STYLE_PROVIDER_PRIORITY_APPLICATION);
    g_object_unref(provider);
}

static void add_column(GtkWidget *tree, const char *title, int col, gboolean mono_right)
{
    GtkCellRenderer *r = gtk_cell_renderer_text_new();
    if (mono_right)
        g_object_set(r, "xalign", 1.0, NULL);
    GtkTreeViewColumn *c =
        gtk_tree_view_column_new_with_attributes(title, r, "text", col, NULL);
    gtk_tree_view_column_set_resizable(c, TRUE);
    gtk_tree_view_column_set_sort_column_id(c, col);
    gtk_tree_view_append_column(GTK_TREE_VIEW(tree), c);
}

static void activate(GtkApplication *gapp, gpointer data)
{
    App *app = data;

    /* Single-instance: a second launch re-emits "activate". Just raise the
     * existing window instead of building a duplicate (which would orphan
     * the first window and its refresh timer). */
    if (app->window) {
        gtk_window_present(GTK_WINDOW(app->window));
        return;
    }

    apply_css();

    app->window = gtk_application_window_new(gapp);
    gtk_window_set_title(GTK_WINDOW(app->window), APP_NAME);
    gtk_window_set_default_size(GTK_WINDOW(app->window), 980, 600);
    gtk_window_set_icon_name(GTK_WINDOW(app->window), "connmon");

    GtkWidget *vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    gtk_container_add(GTK_CONTAINER(app->window), vbox);

    /* ---- Header / toolbar ---- */
    GtkWidget *header = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 10);
    gtk_style_context_add_class(gtk_widget_get_style_context(header), "cyber-header");

    GtkWidget *titlebox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    GtkWidget *title = gtk_label_new("\xe2\x97\x88 CONNECTION MONITOR");
    gtk_widget_set_halign(title, GTK_ALIGN_START);
    gtk_style_context_add_class(gtk_widget_get_style_context(title), "cyber-title");
    GtkWidget *sub = gtk_label_new("real-time TCP socket telemetry");
    gtk_widget_set_halign(sub, GTK_ALIGN_START);
    gtk_style_context_add_class(gtk_widget_get_style_context(sub), "cyber-sub");
    gtk_box_pack_start(GTK_BOX(titlebox), title, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(titlebox), sub, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(header), titlebox, FALSE, FALSE, 0);

    GtkWidget *interval_lbl = gtk_label_new("interval");
    gtk_style_context_add_class(gtk_widget_get_style_context(interval_lbl), "cyber-sub");
    gtk_box_pack_start(GTK_BOX(header), interval_lbl, FALSE, FALSE, 0);

    app->interval_spin = GTK_SPIN_BUTTON(gtk_spin_button_new_with_range(1, 60, 1));
    gtk_spin_button_set_value(app->interval_spin, 2);
    g_signal_connect(app->interval_spin, "value-changed",
                     G_CALLBACK(on_interval_changed), app);
    gtk_box_pack_start(GTK_BOX(header), GTK_WIDGET(app->interval_spin), FALSE, FALSE, 0);

    GtkWidget *about_btn = gtk_button_new_with_label("About");
    g_signal_connect(about_btn, "clicked", G_CALLBACK(on_about_clicked), app);
    gtk_box_pack_end(GTK_BOX(header), about_btn, FALSE, FALSE, 0);

    app->pause_btn = gtk_toggle_button_new_with_label("Pause");
    g_signal_connect(app->pause_btn, "toggled", G_CALLBACK(on_pause_toggled), app);
    gtk_box_pack_end(GTK_BOX(header), app->pause_btn, FALSE, FALSE, 0);

    GtkWidget *refresh_btn = gtk_button_new_with_label("Refresh");
    g_signal_connect(refresh_btn, "clicked", G_CALLBACK(on_refresh_clicked), app);
    gtk_box_pack_end(GTK_BOX(header), refresh_btn, FALSE, FALSE, 0);

    GtkWidget *save_btn = gtk_button_new_with_label("Save");
    g_signal_connect(save_btn, "clicked", G_CALLBACK(on_save_clicked), app);
    gtk_box_pack_end(GTK_BOX(header), save_btn, FALSE, FALSE, 0);

    gtk_box_pack_start(GTK_BOX(vbox), header, FALSE, FALSE, 0);

    /* ---- Connection table ---- */
    app->store = gtk_list_store_new(N_COLS,
        G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING,
        G_TYPE_STRING, G_TYPE_UINT,   G_TYPE_STRING);

    GtkWidget *tree = gtk_tree_view_new_with_model(GTK_TREE_MODEL(app->store));
    gtk_tree_view_set_grid_lines(GTK_TREE_VIEW(tree), GTK_TREE_VIEW_GRID_LINES_HORIZONTAL);
    add_column(tree, "PROTO",   COL_PROTO,   FALSE);
    add_column(tree, "LOCAL",   COL_LOCAL,   FALSE);
    add_column(tree, "REMOTE",  COL_REMOTE,  FALSE);
    add_column(tree, "STATE",   COL_STATE,   FALSE);
    add_column(tree, "UID",     COL_UID,     TRUE);
    add_column(tree, "PROCESS", COL_PROCESS, FALSE);

    GtkWidget *scroll = gtk_scrolled_window_new(NULL, NULL);
    gtk_container_add(GTK_CONTAINER(scroll), tree);
    gtk_box_pack_start(GTK_BOX(vbox), scroll, TRUE, TRUE, 0);

    /* ---- Status bar ---- */
    GtkWidget *statusbar = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 10);
    gtk_style_context_add_class(gtk_widget_get_style_context(statusbar), "status-bar");
    app->status_label = gtk_label_new("Scanning\xe2\x80\xa6");
    gtk_widget_set_halign(app->status_label, GTK_ALIGN_START);
    gtk_style_context_add_class(gtk_widget_get_style_context(app->status_label), "status-text");
    app->count_label = gtk_label_new("");
    gtk_style_context_add_class(gtk_widget_get_style_context(app->count_label), "count-text");
    gtk_box_pack_start(GTK_BOX(statusbar), app->status_label, FALSE, FALSE, 0);
    gtk_box_pack_end(GTK_BOX(statusbar), app->count_label, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(vbox), statusbar, FALSE, FALSE, 0);

    refresh(app);
    restart_timer(app);

    gtk_widget_show_all(app->window);
}

int main(int argc, char **argv)
{
    App app = {0};
    GtkApplication *gapp =
        gtk_application_new(APP_ID, G_APPLICATION_DEFAULT_FLAGS);
    g_signal_connect(gapp, "activate", G_CALLBACK(activate), &app);
    int status = g_application_run(G_APPLICATION(gapp), argc, argv);
    if (app.timer_id)
        g_source_remove(app.timer_id);
    g_object_unref(gapp);
    if (proc_map)
        g_hash_table_destroy(proc_map);
    return status;
}
