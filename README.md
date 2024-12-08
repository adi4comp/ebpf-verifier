# CS6217 Assignment: eBPF Program Verification

This assignment builds upon the **PREVAIL** eBPF verifier repository. Below is a detailed guide for running experiments, synthesizing programs, and verifying them.

---

## Dataset and Program Links

### Dataset Source
- [Eunomia-bpf KEN Dataset](https://github.com/eunomia-bpf/KEN/blob/main/dataset/libbpf/output.json)

### Program Cases

#### **Case 1**
- **Prog 1**: [Link](https://shareclaude.pages.dev/c/p5x3r3e34i31gxdf8lnpxfmi)  
- **Progs 2-7**: [Link](https://shareclaude.pages.dev/c/wjs0zw50r9cm69xh1y80uslp)  
- **Progs 8-10**: [Link](https://shareclaude.pages.dev/c/cp6xa813oelkdoa0yyai6b7z)  

#### **Case 2**
- **Progs 11-15**: [Link](https://shareclaude.pages.dev/c/uwuj9vx8at8of8z67o3nyseq)  
- **Prog 16**: [Link](https://shareclaude.pages.dev/c/y62xt2i9w5b7vn9kz69anrcj)  
- **Progs 17-26**: [Link](https://shareclaude.pages.dev/c/nnu6fq4dn0g8y5b9qam8m28n)  

---

## Results Overview

The following table summarizes the results for each test program:

| **Test File**   | **Status**                                                                 | **Error Message**                               |
|------------------|---------------------------------------------------------------------------|------------------------------------------------|
| `test1.bpf`      | `{'status': 0}`                                                          | N/A                                            |
| `test2.bpf`      | `{'tp_btf/sys_enter': {'status': 0}, 'tp_btf/sys_exit': {'status': 1}}`  | N/A                                            |
| `test3.bpf`      | `{'status': 'error'}`                                                   | `error: BTF type cycle detected: 24`          |
| `test4.bpf`      | `{'status': 'error'}`                                                   | `error: BTF type cycle detected: 34`          |
| `test5.bpf`      | `{'status': 'error'}`                                                   | `error: BTF type cycle detected: 26`          |
| `test6.bpf`      | `{'status': 1}`                                                         | N/A                                            |
| `test7.bpf`      | `{'status': 0}`                                                         | N/A                                            |
| `test8.bpf`      | `{'status': 0}`                                                         | N/A                                            |
| `test9.bpf`      | `{'kprobe/mark_page_accessed': {'status': 0}, 'kprobe/add_to_page_cache_lru': {'status': 0}, 'kprobe/folio_mark_accessed': {'status': 0}}` | N/A |
| `test10.bpf`     | `{'kprobe/inet_csk_accept': {'status': 0}, 'kretprobe/inet_csk_accept': {'status': 1}}` | N/A |
| `test11.bpf`     | `{'status': 0}`                                                         | N/A                                            |
| `test12.bpf`     | `{'status': 1}`                                                         | N/A                                            |
| `test13.bpf`     | `{'status': 1}`                                                         | N/A                                            |
| `test14.bpf`     | `{'kprobe/shrink_node': {'status': 1}, 'kretprobe/shrink_node': {'status': 1}}` | N/A |
| `test15.bpf`     | `{'status': 1}`                                                         | N/A                                            |
| `test16.bpf`     | `{'status': 'error'}`                                                   | `error: BTF type cycle detected: 38`          |
| `test17.bpf`     | `{'status': 1}`                                                         | N/A                                            |
| `test18.bpf`     | `{'status': 1}`                                                         | N/A                                            |
| `test19.bpf`     | `{'status': 1}`                                                         | N/A                                            |
| `test20.bpf`     | `{'kprobe/tcp_v4_syn': {'status': 1}, 'kprobe/tcp_v6_syn': {'status': 1}}` | N/A |
| `test21.bpf`     | `{'kprobe/bpf_jit_binary_alloc': {'status': 1}, 'kprobe/bpf_jit_binary_free': {'status': 1}}` | N/A |
| `test22.bpf`     | `{'status': 1}`                                                         | N/A                                            |
| `test23.bpf`     | `{'kprobe/do_unlinkat': {'status': 1}, 'kretprobe/do_unlinkat': {'status': 1}}` | N/A |
| `test24.bpf`     | `{'status': 1}`                                                         | N/A                                            |
| `test25.bpf`     | `{'status': 0}`                                                         | N/A                                            |
| `test26.bpf`     | `{'status': 1}`                                                         | N/A                                            |

Refer to the raw results section for the complete list.

---

## Experiment Setup

### Steps to Run Experiments

1. **Clone the Repository**
```bash
git clone https://github.com/adi4comp/ebpf-verifier.git
```

2. **Initialize Submodules**

```bash
git submodule update --init --recursive
```

3. **Build the Docker Image**
```bash
docker build -t <tag> .
```

4. **Run the Docker Container**
```bash
docker run -it <tag> bash
```

5. **Interact with the Container**
Inside the container, run the verifier:
```bash
python3 start.py ../check .
```

---

## Program Synthesis

1. Synthesize programs using the dataset and save them in the `CS6217` folder.  
2. Use the provided dockerized setup to verify these programs.

---

## Notes

- Use the links provided in the dataset section to download specific programs.
- Ensure the container is properly built and configured before running experiments.
