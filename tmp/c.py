import re
with open('./raw.txt', 'r') as raw:
    raw_content = raw.read()
    para = raw_content.split('\n\n')
    print(para[1])
    processed = []
    for part in para:
        cleanpart = part.replace('\n', ' ')
        processed.append(cleanpart)
    
    cleaned_content = '\n'.join(processed)
    with open('./clear.txt','a+') as clear:
        clear.write(cleaned_content)