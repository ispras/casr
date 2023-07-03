//! Go module implements `ParseStacktrace` and `Exception` traits for Go panic output.
use crate::exception::Exception;
use crate::stacktrace::ParseStacktrace;

use crate::error::*;
use crate::execution_class::ExecutionClass;
use crate::stacktrace::*;
use regex::Regex;

/// Structure provides an interface for processing stacktrace from Go panics.
pub struct GoStacktrace;

impl ParseStacktrace for GoStacktrace {
    fn extract_stacktrace(stream: &str) -> Result<Vec<String>> {
        let lines = stream
            .split('\n')
            .map(|l| l.to_string())
            .collect::<Vec<String>>();

        let re = Regex::new(r#"goroutine [0-9]+ (?:\[running.*\]|\[syscall\]):"#).unwrap();
        let Some(goroutine_idx) = lines
            .iter()
            .enumerate()
            .position(|(i,line)| re.is_match(line) && i < lines.len() - 1) else {
                return Err(Error::Casr("Couldn't find start of stacktrace in Go panic output".to_string()));
        };

        let lines = &lines[goroutine_idx + 1..];
        let lines = if let Some(end) = lines.iter().position(|s| s.is_empty()) {
            &lines[..end]
        } else {
            lines
        };

        if lines.len() % 2 != 0 {
            return Err(Error::Casr(
                "Go stacktrace line count should be even".to_string(),
            ));
        }

        let mut stacktrace = Vec::new();
        for chunk in lines.chunks(2) {
            let mut entry = String::new();
            entry.push_str(chunk[0].trim());
            entry.push_str(" in ");
            entry.push_str(chunk[1].trim());
            stacktrace.push(entry);
        }
        Ok(stacktrace)
    }

    fn parse_stacktrace_entry(entry: &str) -> Result<StacktraceEntry> {
        let re = Regex::new(r#"(.+) in (.+):([0-9]+)"#).unwrap();
        let mut stentry = StacktraceEntry::default();
        let Some(caps) = re.captures(entry.as_ref()) else {
            return Err(Error::Casr(format!(
                "Couldn't parse stack trace entry: {entry}")
            ));
        };
        stentry.function = caps.get(1).unwrap().as_str().to_string();
        if let Some(file) = caps.get(2) {
            stentry.debug.file = file.as_str().to_string();
            if let Some(line) = caps.get(3) {
                let Ok(num) = line.as_str().parse::<u64>() else {
                    return Err(Error::Casr(format!(
                        "Couldn't parse line number in stack trace entry: {entry}")
                    ));
                };
                stentry.debug.line = num;
            }
        }
        Ok(stentry)
    }
}

/// Structure provides an interface for parsing Go panic message.
pub struct GoPanic;

impl Exception for GoPanic {
    fn parse_exception(stderr: &str) -> Option<ExecutionClass> {
        let re = Regex::new(r#"(runtime error:|panic:|fatal error:) (.+)"#).unwrap();
        let stderr_list: Vec<String> = stderr
            .split('\n')
            .map(|l| l.trim_end().to_string())
            .collect();
        stderr_list.iter().find_map(|x| re.captures(x)).map(|cap| {
            ExecutionClass::new((
                "NOT_EXPLOITABLE",
                "GoPanic",
                cap.get(2).unwrap().as_str(),
                "",
            ))
        })
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_go_panic() {
        let panic_info = "fatal error: runtime: out of memory\n\
\n\
        runtime stack:\n\
        runtime.throw({0x4ef122?, 0x400000?})";
        let Some(class) = GoPanic::parse_exception(panic_info) else {
        panic!("Couldn't get Go panic");
    };

        assert_eq!(class.description, "runtime: out of memory");

        let panic_info = "panic: runtime error: last name cannot be nil\n\
\n\
        goroutine 1 [running]:  \n\
        main.fullName(0xc00006af58, 0x0)";
        let Some(class) = GoPanic::parse_exception(panic_info) else {
        panic!("Couldn't get Go panic");
    };

        assert_eq!(class.description, "runtime error: last name cannot be nil");

        let panic_info = "Error: runtime error: index out of range [0] with length 0\n\
    main.main.func1\n\
        /tmp/sandbox907722598/prog.go:17";
        let Some(class) = GoPanic::parse_exception(panic_info) else {
        panic!("Couldn't get Go panic");
    };

        assert_eq!(class.description, "index out of range [0] with length 0");
    }

    #[test]
    fn test_go_parse_stacktrace() {
        let raw_stacktrace = &[ "runtime.systemstack_switch() in /root/.go/src/runtime/asm_amd64.s:459 fp=0xc00009ac48 sp=0xc00009ac40 pc=0x45bee0",
            "runtime.(*mheap).alloc(0x462ec5?, 0x5a2860?, 0x1?) in /root/.go/src/runtime/mheap.go:904 +0x65 fp=0xc00009ac90 sp=0xc00009ac48 pc=0x425025",
            "runtime.(*mcache).allocLarge(0x511f98?, 0x16a0d1447626, 0x1) in /root/.go/src/runtime/mcache.go:233 +0x85 fp=0xc00009ace0 sp=0xc00009ac90 pc=0x414565",
            "runtime.mallocgc(0x16a0d1447626, 0x4d0ea0, 0x1) in /root/.go/src/runtime/malloc.go:1029 +0x57e fp=0xc00009ad58 sp=0xc00009ace0 pc=0x40bd5e",
            "runtime.makeslice(0xc0000a21b0?, 0xc0000b6030?, 0x8?) in /root/.go/src/runtime/slice.go:103 +0x52 fp=0xc00009ad80 sp=0xc00009ad58 pc=0x447532",
            "golang.org/x/image/webp.readAlpha({0x511ff8, 0xc0000a60a0}, 0xb6030?, 0xc0?, 0x1?) in /image/webp/decode.go:157 +0x29b fp=0xc00009ae18 sp=0xc00009ad80 pc=0x4a775b",
            "golang.org/x/image/webp.decode({0x511f78?, 0xc0000a21b0?}, 0x0) in /image/webp/decode.go:68 +0x354 fp=0xc00009af30 sp=0xc00009ae18 pc=0x4a6f14",
            "golang.org/x/image/webp.Decode(...) in /image/webp/decode.go:255",
            "golang.org/x/image.FuzzWebp({0xc0000cc000, 0x5d, 0x200}) in /image/fuzz.go:22 +0x10c fp=0xc00009af58 sp=0xc00009af30 pc=0x4c572c",
            "main.main() in /image/cmd/sydr_webp/main.go:10 +0x3a fp=0xc00009af80 sp=0xc00009af58 pc=0x4c57da",
            "runtime.main() in /root/.go/src/runtime/proc.go:250 +0x212 fp=0xc00009afe0 sp=0xc00009af80 pc=0x434d12",
            "runtime.goexit() in /root/.go/src/runtime/asm_amd64.s:1594 +0x1 fp=0xc00009afe8 sp=0xc00009afe0 pc=0x45dfc1",
        ];
        let trace = raw_stacktrace
            .iter()
            .map(|e| e.to_string())
            .collect::<Vec<String>>();
        let sttr = GoStacktrace::parse_stacktrace(&trace);
        if sttr.is_err() {
            panic!("{}", sttr.err().unwrap());
        }
        let stacktrace = sttr.unwrap();

        assert_eq!(
            stacktrace[0].function,
            "runtime.systemstack_switch()".to_string()
        );
        assert_eq!(
            stacktrace[0].debug.file,
            "/root/.go/src/runtime/asm_amd64.s".to_string()
        );
        assert_eq!(stacktrace[0].debug.line, 459);

        assert_eq!(
            stacktrace[1].function,
            "runtime.(*mheap).alloc(0x462ec5?, 0x5a2860?, 0x1?)".to_string()
        );
        assert_eq!(
            stacktrace[1].debug.file,
            "/root/.go/src/runtime/mheap.go".to_string()
        );
        assert_eq!(stacktrace[1].debug.line, 904);

        assert_eq!(
            stacktrace[2].function,
            "runtime.(*mcache).allocLarge(0x511f98?, 0x16a0d1447626, 0x1)".to_string()
        );
        assert_eq!(
            stacktrace[2].debug.file,
            "/root/.go/src/runtime/mcache.go".to_string()
        );
        assert_eq!(stacktrace[2].debug.line, 233);

        assert_eq!(
            stacktrace[3].function,
            "runtime.mallocgc(0x16a0d1447626, 0x4d0ea0, 0x1)".to_string()
        );
        assert_eq!(
            stacktrace[3].debug.file,
            "/root/.go/src/runtime/malloc.go".to_string()
        );
        assert_eq!(stacktrace[3].debug.line, 1029);

        assert_eq!(
            stacktrace[4].function,
            "runtime.makeslice(0xc0000a21b0?, 0xc0000b6030?, 0x8?)".to_string()
        );
        assert_eq!(
            stacktrace[4].debug.file,
            "/root/.go/src/runtime/slice.go".to_string()
        );
        assert_eq!(stacktrace[4].debug.line, 103);

        assert_eq!(
            stacktrace[5].function,
            "golang.org/x/image/webp.readAlpha({0x511ff8, 0xc0000a60a0}, 0xb6030?, 0xc0?, 0x1?)"
                .to_string()
        );
        assert_eq!(
            stacktrace[5].debug.file,
            "/image/webp/decode.go".to_string()
        );
        assert_eq!(stacktrace[5].debug.line, 157);

        assert_eq!(
            stacktrace[6].function,
            "golang.org/x/image/webp.decode({0x511f78?, 0xc0000a21b0?}, 0x0)".to_string()
        );
        assert_eq!(
            stacktrace[6].debug.file,
            "/image/webp/decode.go".to_string()
        );
        assert_eq!(stacktrace[6].debug.line, 68);

        assert_eq!(
            stacktrace[7].function,
            "golang.org/x/image/webp.Decode(...)".to_string()
        );
        assert_eq!(
            stacktrace[7].debug.file,
            "/image/webp/decode.go".to_string()
        );
        assert_eq!(stacktrace[7].debug.line, 255);

        assert_eq!(
            stacktrace[8].function,
            "golang.org/x/image.FuzzWebp({0xc0000cc000, 0x5d, 0x200})".to_string()
        );
        assert_eq!(stacktrace[8].debug.file, "/image/fuzz.go".to_string());
        assert_eq!(stacktrace[8].debug.line, 22);

        assert_eq!(stacktrace[9].function, "main.main()".to_string());
        assert_eq!(
            stacktrace[9].debug.file,
            "/image/cmd/sydr_webp/main.go".to_string()
        );
        assert_eq!(stacktrace[9].debug.line, 10);

        assert_eq!(stacktrace[10].function, "runtime.main()".to_string());
        assert_eq!(
            stacktrace[10].debug.file,
            "/root/.go/src/runtime/proc.go".to_string()
        );
        assert_eq!(stacktrace[10].debug.line, 250);

        assert_eq!(stacktrace[11].function, "runtime.goexit()".to_string());
        assert_eq!(
            stacktrace[11].debug.file,
            "/root/.go/src/runtime/asm_amd64.s".to_string()
        );
        assert_eq!(stacktrace[11].debug.line, 1594);
    }

    #[test]
    fn test_go_extract_stacktrace() {
        let output = "fatal error: runtime: out of memory\n\
\n\
runtime stack:\n\
runtime.throw({0x4ef122?, 0x400000?})\n\
	/root/.go/src/runtime/panic.go:1047 +0x5d fp=0x7fffffffe3e0 sp=0x7fffffffe3b0 pc=0x4324bd\n\
runtime.sysMapOS(0xc000400000, 0x16a0d1800000?)\n\
	/root/.go/src/runtime/mem_linux.go:187 +0x11b fp=0x7fffffffe428 sp=0x7fffffffe3e0 pc=0x415bfb\n\
runtime.sysMap(0x5c2d40?, 0x7ffff7f9b000?, 0x428e40?)\n\
	/root/.go/src/runtime/mem.go:142 +0x35 fp=0x7fffffffe458 sp=0x7fffffffe428 pc=0x4155d5\n\
runtime.(*mheap).grow(0x5c2d40, 0xb5068a24?)\n\
	/root/.go/src/runtime/mheap.go:1459 +0x23d fp=0x7fffffffe4c8 sp=0x7fffffffe458 pc=0x425efd\n\
runtime.(*mheap).allocSpan(0x5c2d40, 0xb5068a24, 0x0, 0x1)\n\
	/root/.go/src/runtime/mheap.go:1191 +0x1be fp=0x7fffffffe560 sp=0x7fffffffe4c8 pc=0x42565e\n\
runtime.(*mheap).alloc.func1()\n\
	/root/.go/src/runtime/mheap.go:910 +0x65 fp=0x7fffffffe5a8 sp=0x7fffffffe560 pc=0x4250e5\n\
runtime.systemstack()\n\
	/root/.go/src/runtime/asm_amd64.s:492 +0x49 fp=0x7fffffffe5b0 sp=0x7fffffffe5a8 pc=0x45bf49\n\
\n\
goroutine 1 [running]:\n\
runtime.systemstack_switch()\n\
	/root/.go/src/runtime/asm_amd64.s:459 fp=0xc00009ac48 sp=0xc00009ac40 pc=0x45bee0\n\
runtime.(*mheap).alloc(0x462ec5?, 0x5a2860?, 0x1?)\n\
	/root/.go/src/runtime/mheap.go:904 +0x65 fp=0xc00009ac90 sp=0xc00009ac48 pc=0x425025\n\
runtime.(*mcache).allocLarge(0x511f98?, 0x16a0d1447626, 0x1)\n\
	/root/.go/src/runtime/mcache.go:233 +0x85 fp=0xc00009ace0 sp=0xc00009ac90 pc=0x414565\n\
runtime.mallocgc(0x16a0d1447626, 0x4d0ea0, 0x1)\n\
	/root/.go/src/runtime/malloc.go:1029 +0x57e fp=0xc00009ad58 sp=0xc00009ace0 pc=0x40bd5e\n\
runtime.makeslice(0xc0000a21b0?, 0xc0000b6030?, 0x8?)\n\
	/root/.go/src/runtime/slice.go:103 +0x52 fp=0xc00009ad80 sp=0xc00009ad58 pc=0x447532\n\
golang.org/x/image/webp.readAlpha({0x511ff8, 0xc0000a60a0}, 0xb6030?, 0xc0?, 0x1?)\n\
	/image/webp/decode.go:157 +0x29b fp=0xc00009ae18 sp=0xc00009ad80 pc=0x4a775b\n\
golang.org/x/image/webp.decode({0x511f78?, 0xc0000a21b0?}, 0x0)\n\
	/image/webp/decode.go:68 +0x354 fp=0xc00009af30 sp=0xc00009ae18 pc=0x4a6f14\n\
golang.org/x/image/webp.Decode(...)\n\
	/image/webp/decode.go:255\n\
golang.org/x/image.FuzzWebp({0xc0000cc000, 0x5d, 0x200})\n\
	/image/fuzz.go:22 +0x10c fp=0xc00009af58 sp=0xc00009af30 pc=0x4c572c\n\
main.main()\n\
	/image/cmd/sydr_webp/main.go:10 +0x3a fp=0xc00009af80 sp=0xc00009af58 pc=0x4c57da\n\
runtime.main()\n\
	/root/.go/src/runtime/proc.go:250 +0x212 fp=0xc00009afe0 sp=0xc00009af80 pc=0x434d12\n\
runtime.goexit()\n\
	/root/.go/src/runtime/asm_amd64.s:1594 +0x1 fp=0xc00009afe8 sp=0xc00009afe0 pc=0x45dfc1\n\
\n\
goroutine 2 [force gc (idle)]:\n\
runtime.gopark(0x0?, 0x0?, 0x0?, 0x0?, 0x0?)\n\
	/root/.go/src/runtime/proc.go:363 +0xd6 fp=0xc000046fb0 sp=0xc000046f90 pc=0x4350d6\n\
runtime.goparkunlock(...)\n\
	/root/.go/src/runtime/proc.go:369\n\
runtime.forcegchelper()\n\
	/root/.go/src/runtime/proc.go:302 +0xad fp=0xc000046fe0 sp=0xc000046fb0 pc=0x434f6d\n\
runtime.goexit()\n\
	/root/.go/src/runtime/asm_amd64.s:1594 +0x1 fp=0xc000046fe8 sp=0xc000046fe0 pc=0x45dfc1\n\
created by runtime.init.6\n\
	/root/.go/src/runtime/proc.go:290 +0x25";

        let raw_stacktrace = &["runtime.systemstack_switch() in /root/.go/src/runtime/asm_amd64.s:459 fp=0xc00009ac48 sp=0xc00009ac40 pc=0x45bee0",
            "runtime.(*mheap).alloc(0x462ec5?, 0x5a2860?, 0x1?) in /root/.go/src/runtime/mheap.go:904 +0x65 fp=0xc00009ac90 sp=0xc00009ac48 pc=0x425025",
            "runtime.(*mcache).allocLarge(0x511f98?, 0x16a0d1447626, 0x1) in /root/.go/src/runtime/mcache.go:233 +0x85 fp=0xc00009ace0 sp=0xc00009ac90 pc=0x414565",
            "runtime.mallocgc(0x16a0d1447626, 0x4d0ea0, 0x1) in /root/.go/src/runtime/malloc.go:1029 +0x57e fp=0xc00009ad58 sp=0xc00009ace0 pc=0x40bd5e",
            "runtime.makeslice(0xc0000a21b0?, 0xc0000b6030?, 0x8?) in /root/.go/src/runtime/slice.go:103 +0x52 fp=0xc00009ad80 sp=0xc00009ad58 pc=0x447532",
            "golang.org/x/image/webp.readAlpha({0x511ff8, 0xc0000a60a0}, 0xb6030?, 0xc0?, 0x1?) in /image/webp/decode.go:157 +0x29b fp=0xc00009ae18 sp=0xc00009ad80 pc=0x4a775b",
            "golang.org/x/image/webp.decode({0x511f78?, 0xc0000a21b0?}, 0x0) in /image/webp/decode.go:68 +0x354 fp=0xc00009af30 sp=0xc00009ae18 pc=0x4a6f14",
            "golang.org/x/image/webp.Decode(...) in /image/webp/decode.go:255",
            "golang.org/x/image.FuzzWebp({0xc0000cc000, 0x5d, 0x200}) in /image/fuzz.go:22 +0x10c fp=0xc00009af58 sp=0xc00009af30 pc=0x4c572c",
            "main.main() in /image/cmd/sydr_webp/main.go:10 +0x3a fp=0xc00009af80 sp=0xc00009af58 pc=0x4c57da",
            "runtime.main() in /root/.go/src/runtime/proc.go:250 +0x212 fp=0xc00009afe0 sp=0xc00009af80 pc=0x434d12",
            "runtime.goexit() in /root/.go/src/runtime/asm_amd64.s:1594 +0x1 fp=0xc00009afe8 sp=0xc00009afe0 pc=0x45dfc1",
        ];
        let trace = raw_stacktrace
            .iter()
            .map(|e| e.to_string())
            .collect::<Vec<String>>();

        let sttr = GoStacktrace::extract_stacktrace(output);
        if sttr.is_err() {
            panic!("{}", sttr.err().unwrap());
        }

        let stacktrace = sttr.unwrap();

        assert_eq!(stacktrace, trace);

        let output = "fatal error: unexpected signal during runtime execution\n\
[signal 0xb code=0x2 addr=0x7fed87890340 pc=0x7fed91e2de3e]\n\
\n\
runtime stack:\n\
runtime: unexpected return pc for runtime.sigpanic called from 0x7fed91e2de3e\n\
runtime.throw(0x88bcc5)\n\
        /usr/local/go/src/pkg/runtime/panic.c:520 +0x69\n\
runtime: unexpected return pc for runtime.sigpanic called from 0x7fed91e2de3e\n\
runtime.sigpanic()\n\
        /usr/local/go/src/pkg/runtime/os_linux.c:222 +0x3d\n\
\n\
goroutine 16 [syscall]:\n\
runtime.cgocall(0x401550, 0xc213ca98e8)\n\
        /usr/local/go/src/pkg/runtime/cgocall.c:143 +0xe5 fp=0xc213ca98d0 sp=0xc213ca9888\n\
private/leptonica._Cfunc_pixClipRectangle(0x7fed8788ff00, 0x7fed8788ffd0, 0x0, 0x8c2a28)\n\
        private/leptonica/_obj/_cgo_defun.c:80 +0x31 fp=0xc213ca98e8 sp=0xc213ca98d0\n\
private/leptonica.(*goPix).Crop(0xc20af90000, 0x900, 0x90, 0x4d8, 0x9a8, 0x4202c1, 0x0, 0x0)\n\
        /home/go/src/private/leptonica/leptonica.go:154 +0xd8 fp=0xc213ca9960 sp=0xc213ca98e8\n\
main.(*pageStruct).transformOriginal(0xc20805ae10, 0xc224772000, 0x69, 0x1)\n\
        /home/root/go/frankenstein.go:1353 +0x30d fp=0xc213ca99c8 sp=0xc213ca9960\n\
main.(*pageStruct).transformOriginalWithRecover(0xc20805ae10, 0xc224772000, 0x69, 0x1, 0x0, 0x5, 0x0, 0x0)\n\
        /home/root/go/frankenstein.go:1403 +0xe1 fp=0xc213ca9a38 sp=0xc213ca99c8\n\
main.(*book).processPages(0xc208a90000, 0x0, 0x0)\n\
        /home/root/go/frankenstein.go:1542 +0x305 fp=0xc213ca9e48 sp=0xc213ca9a38\n\
main.main()\n\
        /home/root/go/frankenstein.go:1970 +0x3f5 fp=0xc213ca9f50 sp=0xc213ca9e48\n\
runtime.main()\n\
        /usr/local/go/src/pkg/runtime/proc.c:247 +0x11a fp=0xc213ca9fa8 sp=0xc213ca9f50\n\
runtime.goexit()\n\
        /usr/local/go/src/pkg/runtime/proc.c:1445 fp=0xc213ca9fb0 sp=0xc213ca9fa8\n\
created by _rt0_go\n\
        /usr/local/go/src/pkg/runtime/asm_amd64.s:97 +0x120";

        let raw_stacktrace = &["runtime.cgocall(0x401550, 0xc213ca98e8) in /usr/local/go/src/pkg/runtime/cgocall.c:143 +0xe5 fp=0xc213ca98d0 sp=0xc213ca9888",
            "private/leptonica._Cfunc_pixClipRectangle(0x7fed8788ff00, 0x7fed8788ffd0, 0x0, 0x8c2a28) in private/leptonica/_obj/_cgo_defun.c:80 +0x31 fp=0xc213ca98e8 sp=0xc213ca98d0",
            "private/leptonica.(*goPix).Crop(0xc20af90000, 0x900, 0x90, 0x4d8, 0x9a8, 0x4202c1, 0x0, 0x0) in /home/go/src/private/leptonica/leptonica.go:154 +0xd8 fp=0xc213ca9960 sp=0xc213ca98e8",
            "main.(*pageStruct).transformOriginal(0xc20805ae10, 0xc224772000, 0x69, 0x1) in /home/root/go/frankenstein.go:1353 +0x30d fp=0xc213ca99c8 sp=0xc213ca9960",
            "main.(*pageStruct).transformOriginalWithRecover(0xc20805ae10, 0xc224772000, 0x69, 0x1, 0x0, 0x5, 0x0, 0x0) in /home/root/go/frankenstein.go:1403 +0xe1 fp=0xc213ca9a38 sp=0xc213ca99c8",
            "main.(*book).processPages(0xc208a90000, 0x0, 0x0) in /home/root/go/frankenstein.go:1542 +0x305 fp=0xc213ca9e48 sp=0xc213ca9a38",
            "main.main() in /home/root/go/frankenstein.go:1970 +0x3f5 fp=0xc213ca9f50 sp=0xc213ca9e48",
            "runtime.main() in /usr/local/go/src/pkg/runtime/proc.c:247 +0x11a fp=0xc213ca9fa8 sp=0xc213ca9f50",
            "runtime.goexit() in /usr/local/go/src/pkg/runtime/proc.c:1445 fp=0xc213ca9fb0 sp=0xc213ca9fa8",
            "created by _rt0_go in /usr/local/go/src/pkg/runtime/asm_amd64.s:97 +0x120"
        ];
        let trace = raw_stacktrace
            .iter()
            .map(|e| e.to_string())
            .collect::<Vec<String>>();
        let sttr = GoStacktrace::extract_stacktrace(output);
        if sttr.is_err() {
            panic!("{}", sttr.err().unwrap());
        }

        let stacktrace = sttr.unwrap();

        assert_eq!(stacktrace, trace);
    }
}
