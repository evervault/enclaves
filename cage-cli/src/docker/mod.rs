pub mod parse;
use parse::Instruction;

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

pub fn create_combined_docker_entrypoint(entrypoint: Option<Instruction>, cmd: Option<Instruction>) -> String {
    match (entrypoint.as_ref(), cmd.as_ref()) {
        (Some(entrypoint), None) => entrypoint.to_string(),
        (None, Some(cmd)) => cmd.to_string(),
        (Some(entrypoint), Some(cmd)) => {
            if entrypoint.mode().unwrap().is_shell() {
                entrypoint.to_string()
            } else {
                // TODO: this should be composing terms, not full directives
                format!("{} {}", entrypoint.to_string(), cmd.to_string())
            }
        },
        (None, None) => panic!("Either entrypoint or cmd must be specified")
    }
}
