all: ipac_watchpoint_app ptrace_watchpoint

ipac_watchpoint_app: ipac_watchpoint_app.c
	gcc -o ipac_watchpoint_app ipac_watchpoint_app.c

ptrace_watchpoint: ptrace_watchpoint.c
	gcc -o ptrace_watchpoint ptrace_watchpoint.c

clean:
	rm ipac_watchpoint_app ptrace_watchpoint