pub mod parse;
pub mod enclave_builder;
use parse::Directive;
use itertools::join;

/*
 Expected behaviour of various ENTRYPOINT/CMD combos in dockerfiles.
 src: https://docs.docker.com/engine/reference/builder/#understand-how-cmd-and-entrypoint-interact
 Shell form: [DIRECTIVE] arg1 arg2 arg3...
 Exec form: [DIRECTIVE] ["arg1", "arg2", "arg3", ...]
+----------------------------+----------------------------+--------------------------------+------------------------------------------------+
|             —              |       No ENTRYPOINT        | ENTRYPOINT exec_entry p1_entry |     ENTRYPOINT ["exec_entry", "p1_entry"]      |
+----------------------------+----------------------------+--------------------------------+------------------------------------------------+
| No CMD                     | error, not allowed         | /bin/sh -c exec_entry p1_entry | exec_entry p1_entry                            |
| CMD ["exec_cmd", "p1_cmd"] | exec_cmd p1_cmd            | /bin/sh -c exec_entry p1_entry | exec_entry p1_entry exec_cmd p1_cmd            |
| CMD ["p1_cmd", "p2_cmd"]   | p1_cmd p2_cmd              | /bin/sh -c exec_entry p1_entry | exec_entry p1_entry p1_cmd p2_cmd              |
| CMD exec_cmd p1_cmd        | /bin/sh -c exec_cmd p1_cmd | /bin/sh -c exec_entry p1_entry | exec_entry p1_entry /bin/sh -c exec_cmd p1_cmd |
+----------------------------+----------------------------+--------------------------------+------------------------------------------------+
*/

pub fn create_combined_docker_entrypoint(entrypoint: Option<Directive>, cmd: Option<Directive>) -> String {
    let format_tokens = |tokens: &[String]| -> String {
        join(tokens, " ")
    };
    match (entrypoint.as_ref(), cmd.as_ref()) {
        (Some(entrypoint), None) => format_tokens(entrypoint.tokens().unwrap()),
        (None, Some(cmd)) => format_tokens(cmd.tokens().unwrap()),
        (Some(entrypoint), Some(cmd)) => {
            if entrypoint.mode().unwrap().is_shell() {
                format_tokens(entrypoint.tokens().unwrap())
            } else {
                format!("{} {}", format_tokens(entrypoint.tokens().unwrap()), format_tokens(cmd.tokens().unwrap()))
            }
        },
        (None, None) => panic!("Either entrypoint or cmd must be specified")
    }
}
