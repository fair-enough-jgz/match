# vulmine

## 简介

Vulmine是一个基于程序分析和大模型进行漏洞挖掘和PoC生成的项目。主要包含以下关键步骤：
1. 通过codeql扫描源码获得可能的漏洞点
2. 通过大模型理解可能的漏洞点并尝试生成PoC
3. 基于运行结果反馈，大模型经过多轮迭代调整PoC，直到触发漏洞

## 运行方式

./vulmine/run.sh

## 注意事项

1. 当替换调用的大模型时，可能需要修改app.py中以下代码：

    client = AzureOpenAI(
        api_key=configs["gpt_4o_key"],
        api_version="2024-02-01",
        azure_endpoint=configs["gpt_4o_url"],
    )

        response = client.chat.completions.create(
            model="gpt-4o",
            messages=conversation_history,
        )

