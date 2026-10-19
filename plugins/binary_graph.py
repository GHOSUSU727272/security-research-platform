"""Conservative Capstone control-flow and call edges for supported ELF machines."""

from pathlib import Path
from typing import Any

import capstone as cs
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection


def binary_graph(path: Path, limit: int) -> dict[str, Any]:
    """Disassemble executable sections and preserve unresolved indirect transfers."""
    with path.open("rb") as stream:
        elf = ELFFile(stream)
        machine = elf["e_machine"]
        if elf["e_type"] == "ET_REL":
            raise ValueError(
                "Relocatable objects require section-relative relocation analysis; use Ghidra backend"
            )
        modes = {
            "EM_X86_64": (cs.CS_ARCH_X86, cs.CS_MODE_64),
            "EM_386": (cs.CS_ARCH_X86, cs.CS_MODE_32),
            "EM_AARCH64": (
                cs.CS_ARCH_ARM64,
                cs.CS_MODE_LITTLE_ENDIAN
                if elf.little_endian
                else cs.CS_MODE_BIG_ENDIAN,
            ),
        }
        if machine not in modes:
            raise ValueError(
                f"Capstone graph backend does not support {machine}; use Ghidra backend"
            )
        decoder = cs.Cs(*modes[machine])
        decoder.detail = True
        decoder.skipdata = True
        functions: dict[int, dict[str, Any]] = {}
        for section in elf.iter_sections():
            if isinstance(section, SymbolTableSection):
                for symbol in section.iter_symbols():
                    if (
                        symbol["st_info"]["type"] == "STT_FUNC"
                        and symbol["st_shndx"] != "SHN_UNDEF"
                    ):
                        address = int(symbol["st_value"])
                        functions[address] = {
                            "name": symbol.name or f"sub_{address:x}",
                            "address": address,
                            "size": symbol["st_size"],
                        }
        instructions: list[dict[str, Any]] = []
        truncated = False
        for section in elf.iter_sections():
            if not section["sh_flags"] & 4 or section["sh_type"] != "SHT_PROGBITS":
                continue
            for instruction in decoder.disasm(section.data(), section["sh_addr"]):
                if len(instructions) >= limit:
                    truncated = True
                    break
                item: dict[str, Any] = {
                    "address": instruction.address,
                    "size": instruction.size,
                    "mnemonic": instruction.mnemonic,
                    "operands": instruction.op_str,
                    "section": section.name,
                    "call": False,
                    "jump": False,
                    "return": False,
                    "gap": instruction.id == 0,
                }
                if instruction.id:
                    item.update(
                        call=instruction.group(cs.CS_GRP_CALL),
                        jump=instruction.group(cs.CS_GRP_JUMP),
                        **{"return": instruction.group(cs.CS_GRP_RET)},
                    )
                    if item["call"] or item["jump"]:
                        immediates = [
                            operand.imm
                            for operand in instruction.operands
                            if operand.type == 2
                        ]
                        item["target"] = immediates[-1] if immediates else None
                instructions.append(item)
            if truncated:
                break
    addresses = {i["address"] for i in instructions}
    sections = {i["address"]: i["section"] for i in instructions}
    leaders = {i["address"] for i in instructions if i["address"] in functions}
    for i, instruction in enumerate(instructions):
        if i == 0 or instructions[i - 1]["section"] != instruction["section"]:
            leaders.add(instruction["address"])
        if instruction.get("target") in addresses:
            leaders.add(instruction["target"])
        if instruction["jump"] or instruction["return"] or instruction["gap"]:
            if i + 1 < len(instructions):
                leaders.add(instructions[i + 1]["address"])
    blocks: list[dict[str, Any]] = []
    address_block: dict[int, int] = {}
    for instruction in instructions:
        if not blocks or instruction["address"] in leaders:
            blocks.append(
                {
                    "id": instruction["address"],
                    "section": instruction["section"],
                    "instructions": [],
                }
            )
        blocks[-1]["instructions"].append(instruction)
        address_block[instruction["address"]] = blocks[-1]["id"]
    edges: list[dict[str, Any]] = []
    calls: list[dict[str, Any]] = []
    sorted_functions = sorted(functions)

    def owner(address: int) -> str:
        """Resolve only function ranges established by symbol metadata."""
        import bisect

        index = bisect.bisect_right(sorted_functions, address) - 1
        if index >= 0:
            f = functions[sorted_functions[index]]
            if (
                f["address"] == address
                or f["size"]
                and address < f["address"] + f["size"]
            ):
                return str(f["name"])
        return f"address_{address:x}"

    for block in blocks:
        last = block["instructions"][-1]
        next_address = last["address"] + last["size"]
        if last["jump"]:
            target = last.get("target")
            edges.append(
                {
                    "source": block["id"],
                    "target": address_block.get(target),
                    "target_address": target,
                    "type": "branch" if target is not None else "unresolved",
                    "expression": last["operands"],
                }
            )
        unconditional = last["mnemonic"] in {"jmp", "b", "br"}
        if (
            not last["return"]
            and not last["gap"]
            and not unconditional
            and next_address in address_block
            and sections[next_address] == last["section"]
        ):
            edges.append(
                {
                    "source": block["id"],
                    "target": address_block[next_address],
                    "type": "fallthrough",
                }
            )
        for instruction in block["instructions"]:
            if instruction["call"]:
                target = instruction.get("target")
                calls.append(
                    {
                        "caller": owner(instruction["address"]),
                        "callee": owner(target) if target is not None else None,
                        "address": instruction["address"],
                        "target_address": target,
                        "type": "direct" if target is not None else "unresolved",
                        "expression": instruction["operands"],
                    }
                )
    return {
        "backend": "capstone",
        "machine": machine,
        "functions": list(functions.values()),
        "blocks": blocks,
        "edges": edges,
        "calls": calls,
        "instructions": len(instructions),
        "truncated": truncated,
        "limitations": [
            "Linear section disassembly can include embedded data",
            "Indirect targets and stripped function boundaries remain unresolved",
        ],
    }
