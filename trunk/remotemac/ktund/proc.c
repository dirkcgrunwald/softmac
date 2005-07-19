#include <linux/sysctl.h>
#include <asm/atomic.h>

extern char ktund_server_name[256];
extern int  ktund_server_port;
extern int  ktund_start;
extern int  ktund_stop;
extern int  ktund_unload;
extern atomic_t ktund_stop_count;

extern int ktund_tunnel_send(char *buf, int len);

static int 
stop_count_dointvec(ctl_table *table, int write, struct file *filp,
			void *buffer, size_t *lenp, loff_t *loff)
{
    int ret;
    int oldstop = ktund_stop;
    ret = proc_dointvec(table, write, filp, buffer, lenp, loff);
    if (ktund_stop && !oldstop)
	atomic_inc(&ktund_stop_count);
    
    return ret;
}

enum {
    NET_KTUND_SERVERNAME = 1,
    NET_KTUND_SERVERPORT = 2,
    NET_KTUND_START      = 3,
    NET_KTUND_STOP       = 4,
    NET_KTUND_UNLOAD     = 5,
};

static ctl_table ktund_table[] = {
    {	NET_KTUND_SERVERNAME,
	"server_name",
	&ktund_server_name,
	sizeof(ktund_server_name),
	0644,
	NULL,
	proc_dostring,
	&sysctl_string,
	NULL,
	NULL,
	NULL
    },
    {	NET_KTUND_SERVERPORT,
	"server_port",
	&ktund_server_port,
	sizeof(ktund_server_port),
	0644,
	NULL,
	proc_dointvec,
	&sysctl_intvec,
	NULL,
	NULL,
	NULL
    },
    {	NET_KTUND_START,
	"start",
	&ktund_start,
	sizeof(ktund_start),
	0644,
	NULL,
	proc_dointvec,
	&sysctl_intvec,
	NULL,
	NULL,
	NULL
    },
    {	NET_KTUND_STOP,
	"stop",
	&ktund_stop,
	sizeof(ktund_stop),
	0644,
	NULL,
	stop_count_dointvec,
	&sysctl_intvec,
	NULL,
	NULL,
	NULL
    },
    {	NET_KTUND_UNLOAD,
	"unload",
	&ktund_unload,
	sizeof(ktund_unload),
	0644,
	NULL,
	proc_dointvec,
	&sysctl_intvec,
	NULL,
	NULL,
	NULL
    },
    {0,0,0,0,0,0,0,0,0,0,0}
};

static ctl_table ktund_dir_table[] = {
    {19 /*19 = NET_SCTP+1 is first unused*/, 
     "ktund", NULL, 0, 0555, ktund_table,0,0,0,0,0},
    {0,0,0,0,0,0,0,0,0,0,0}
};

static ctl_table ktund_root_table[] = {
    {CTL_NET, "net", NULL, 0, 0555, ktund_dir_table,0,0,0,0,0},
    {0,0,0,0,0,0,0,0,0,0,0}
};

static struct ctl_table_header *ktund_table_header;

void 
ktund_proc_start(void)
{
    ktund_table_header = register_sysctl_table(ktund_root_table,1);
}

void 
ktund_proc_stop(void)
{
    unregister_sysctl_table(ktund_table_header);
}
