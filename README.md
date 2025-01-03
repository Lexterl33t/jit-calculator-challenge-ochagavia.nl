# Jit Calculator

## Introduction

This challenge has been started by Adolfo Ochagavía [here](https://ochagavia.nl/blog/the-jit-calculator-challenge/)

## Final solution

```rs
use libc::{
    MAP_ANON, MAP_PRIVATE, PROT_EXEC, PROT_READ, PROT_WRITE, int32_t, int64_t, mmap, mprotect,
    munmap,
};
use std::{ptr, slice};

struct Compiler {}

impl Compiler {
    pub fn emitXorRaxRax(&self) -> Vec<u8> {
        return [0x48, 0x31, 0xc0].to_vec();
    }

    pub fn emitAddRax1(&self) -> Vec<u8> {
        return [0x48, 0x83, 0xc0, 0x01].to_vec();
    }

    pub fn emitSubRax1(&self) -> Vec<u8> {
        return [0x48, 0x83, 0xe8, 0x01].to_vec();
    }

    pub fn emitMulRax2(&self) -> Vec<u8> {
        // \x48\xc7\xc3\x02\x00\x00\x00\x48\xf7\xe3
        return [0x48, 0xc7, 0xc3, 0x02, 0x00, 0x00, 0x00, 0x48, 0xf7, 0xe3].to_vec();
    }

    pub fn emitDivRax2(&self) -> Vec<u8> {
        // "\x48\xc7\xc3\x02\x00\x00\x00\x48\xf7\xf3"
        return [0x48, 0xc7, 0xc3, 0x02, 0x00, 0x00, 0x00, 0x48, 0xf7, 0xf3].to_vec();
    }

    pub fn emitPushRax(&self) -> Vec<u8> {
        return [0x50].to_vec();
    }

    pub fn emitPushRbx(&self) -> Vec<u8> {
        return [0x53].to_vec();
    }

    pub fn emitRet(&self) -> Vec<u8> {
        return [0xc3].to_vec();
    }
}

/*
MOV RAX, 0x0 ; acumulator <- 0
ADD RAX, 1 ; acumulator <- acumulator + 1
ADD RAX, 1 ; acumulator <- acumulator + 1
MUL RAX, 2 ; acumulator <- acumulator * 2
SUB RAX, 1 ; acumulator <- acumulator - 1
DIV RAX, 2 ; acumulator <- acumulator / 2
RET
*/

fn jit_program(my_input_program: &str) -> Vec<u8> {
    let mut program_jitted: Vec<u8> = Vec::new();
    let compiler = Compiler {};
    program_jitted.append(&mut compiler.emitXorRaxRax());
    for token in my_input_program.chars() {
        match token {
            '+' => program_jitted.append(&mut compiler.emitAddRax1()),
            '-' => program_jitted.append(&mut compiler.emitSubRax1()),
            '*' => program_jitted.append(&mut compiler.emitMulRax2()),
            '/' => program_jitted.append(&mut compiler.emitDivRax2()),
            _ => {}
        }
    }
    program_jitted.append(&mut compiler.emitRet());
    return program_jitted;
}

fn run_machine_code(machine_code: Vec<u8>) -> i64 {
    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) as usize };

    let shellcode_len = machine_code.len();
    let alloc_size = ((shellcode_len + page_size - 1) / page_size) * page_size;

    let exec_mem = unsafe {
        mmap(
            ptr::null_mut(),
            alloc_size,
            PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANON,
            -1,
            0,
        )
    };

    if exec_mem == libc::MAP_FAILED {
        panic!("Failed to allocate executable memory with mmap");
    }

    unsafe {
        let exec_mem_slice = slice::from_raw_parts_mut(exec_mem as *mut u8, shellcode_len);
        exec_mem_slice.copy_from_slice(&machine_code);
    }

    unsafe {
        if mprotect(exec_mem, alloc_size, PROT_READ | PROT_EXEC) != 0 {
            panic!("Failed to set memory as executable with mprotect");
        }
    }

    let shellcode_func: extern "C" fn() -> i64 = unsafe { std::mem::transmute(exec_mem) };
    println!("Executing shellcode...");
    let result: i64 = shellcode_func();

    unsafe {
        if munmap(exec_mem, alloc_size) != 0 {
            panic!("Failed to free allocated memory with munmap");
        }
    }

    return result;
}

fn main() {
    let program = "+ + * - / + ";

    let machine_code = jit_program(program);

    let ret = run_machine_code(machine_code);

    println!("Accumulator: {}", ret);
}
```
