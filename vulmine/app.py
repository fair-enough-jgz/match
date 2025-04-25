from flask import Flask, request, redirect, url_for, jsonify, Response, render_template, send_from_directory
from models import db, Task, Vul, Rule
import datetime
from collections import defaultdict
import os
import threading
import json
import subprocess
import pandas
from openai import OpenAI, AzureOpenAI
import _thread as thread
from werkzeug.utils import secure_filename
import re
import shutil
import zipfile


def load_config():
    with open("/home/jgz/vulmine/config.json", "r") as f:
        return json.load(f)


configs = load_config()


class Config:
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_DATABASE_URI = "sqlite:///" + configs["data_dir"] + "site.db"


app = Flask(__name__)
app.config.from_object(Config)

db.init_app(app)
with app.app_context():
    db.create_all()

os.makedirs(configs["data_dir"]+"uploads", exist_ok=True)

output = []
task_status = ""
conversation_history = []


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/source")
def source():
    tasks = Task.query.filter_by(type="source").all()
    return render_template("source/source.html", tasks=tasks)


def unzip_file(zip_path, extract_path):
    command = ["unzip", "-o", zip_path, "-d", extract_path]
    process = subprocess.run(
        command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    if process.returncode == 0:
        print(f"解压成功: {zip_path} → {extract_path}")
    else:
        print(f"解压失败: {process.stderr}")


@app.route("/createSourceTask", methods=["POST"])
def createSourceTask():
    name = request.form.get("taskName")
    target = os.path.join(configs["data_dir"]+"code/")
    file = request.files["sourceFile"]
    if file:
        filename = secure_filename(file.filename)
        file_path = os.path.join(configs["data_dir"]+"code/", filename)
        file.save(file_path)
        unzip_file(file_path, target)
        target += filename.split(".")[0]

    compileCommand = request.form.get("compileCommand")
    runCommand = request.form.get("runCommand")
    input = request.form.get("input")
    createTime = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    new_task = Task(
        type="source",
        name=name,
        target=target,
        compileCommand=compileCommand,
        runCommand=runCommand,
        input=input,
        createTime=createTime,
    )
    db.session.add(new_task)
    db.session.commit()
    return redirect(url_for("source"))


@app.route("/supplementVul", methods=["POST"])
def supplementVul():
    vul_id = request.form.get("vul_id")
    vulReport = request.form.get("vulReport")
    vulPatch = request.form.get("vulPatch")

    vul = Vul.query.get_or_404(vul_id)
    vul.vulReport = vulReport
    vul.vulPatch = vulPatch
    db.session.commit()
    return "已更新"


@app.route("/deleteSourceTask/<int:id>", methods=["GET"])
def deleteSourceTask(id):
    task = Task.query.get_or_404(id)
    Vul.query.filter_by(task_id=task.id).delete()
    db.session.delete(task)
    db.session.commit()
    return redirect(url_for("source"))


@app.route('/download/<filename>')
def downloadFile(filename):
    print(filename)
    try:
        return send_from_directory(configs["data_dir"]+"poc/", filename, as_attachment=True)
    except Exception as e:
        return str(e), 400


@app.route("/viewSourceTask/<int:id>", methods=["GET"])
def viewSourceTask(id):
    task = Task.query.get_or_404(id)
    vuls_by_rule = defaultdict(list)
    bugs = Vul.query.filter_by(task_id=id).all()
    for vul in bugs:
        vuls_by_rule[vul.rule_id].append(vul)

    results = []
    for rule_id, vuls in vuls_by_rule.items():
        rule = Rule.query.get_or_404(rule_id)
        vul_rule = {}
        vul_rule["rule_name"] = rule.rule_name
        vul_rule["rule_description"] = rule.rule_description
        vul_rule["threat_level"] = rule.threat_level
        vul_rule["vuls"] = []
        for vul in vuls:
            bug = {}
            bug["id"] = vul.id
            bug["vulnerability_description"] = vul.vulnerability_description
            bug["source_file"] = vul.source_file
            bug["poc"] = vul.poc
            bug["poc_python"] = str(vul.id)+"_python.py"
            bug["vul_report"] = vul.vulReport
            bug["vul_patch"] = vul.vulPatch
            pre_code_lines = []
            pre_line_numbers = []
            code_lines = []
            line_numbers = []
            post_code_lines = []
            post_line_numbers = []
            source_file = task.target + vul.source_file
            if os.path.exists(source_file):
                with open(source_file, "r") as file:
                    lines = file.readlines()
                    total_lines = len(lines)
                    start_line = max(
                        1, min(int(vul.start_line), total_lines)) - 1
                    pre_line = max(1, min(start_line - 4, total_lines)) - 1
                    end_line = max(start_line, min(
                        int(vul.end_line), total_lines)) - 1
                    post_line = max(
                        end_line + 1, min(end_line + 6, total_lines)) - 1
                    count = pre_line + 1
                    for line in lines[pre_line:start_line]:
                        pre_line_numbers.append(str(count))
                        pre_code_lines.append(line)
                        count += 1
                    bug["pre_lines"] = zip(pre_line_numbers, pre_code_lines)
                    for line in lines[start_line: end_line + 1]:
                        line_numbers.append(str(count))
                        code_lines.append(line)
                        count += 1
                    bug["code_lines"] = zip(line_numbers, code_lines)
                    for line in lines[end_line + 1: post_line + 1]:
                        post_line_numbers.append(str(count))
                        post_code_lines.append(line)
                        count += 1
                    bug["post_lines"] = zip(post_line_numbers, post_code_lines)

            vul_rule["vuls"].append(bug)

        results.append(vul_rule)

    return render_template("source/source_task.html", task=task, results=results)


@app.route("/startSourceTask", methods=["POST"])
def startSourceTask():
    id = request.args.get("id")
    task = Task.query.get_or_404(id)
    code_dir = task.target
    db_dir = configs["data_dir"]+"db/" + task.name
    result_dir = configs["data_dir"]+"result/" + task.name + ".csv"
    task_thread = threading.Thread(
        target=execute_task, args=(
            code_dir, db_dir, result_dir, task.id)
    )
    task_thread.start()
    return jsonify({"status": "task started."})


def execute_task(code_dir, db_dir, result_dir, task_id):
    global output
    global task_status
    task_status = "success"
    output.append("开始漏洞扫描.")

    if os.path.exists(db_dir):
        output.append("源代码数据库已存在.")
    else:
        command = [
            configs["codeql_path"],
            "database",
            "create",
            db_dir,
            "--language=c",
            "--source-root",
            code_dir,
        ]
        print(f"执行命令：{' '.join(command)}")
        try:
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            for line in process.stdout:
                output.append(line.strip())

            for line in process.stderr:
                output.append(line.strip())

            process.wait()
            output.append("源代码数据库创建完成.")

        except Exception as e:
            output.append(f"源代码数据库创建失败，异常信息: {str(e)}")
            task_status = "fail"

    if task_status == "success":
        if os.path.exists(result_dir):
            output.append("漏洞扫描结果已存在.")
        else:
            command = [
                configs["codeql_path"],
                "database",
                "analyze",
                db_dir,
                "--format=CSV",
                "--output=" + result_dir,
                "--download",
                "codeql/cpp-queries"
            ]
            print(f"执行命令：{' '.join(command)}")
            try:
                process = subprocess.Popen(
                    command,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True
                )
                for line in process.stdout:
                    output.append(line.strip())

                for line in process.stderr:
                    output.append(line.strip())

                process.wait()
                output.append("漏洞扫描完成.")

            except Exception as e:
                output.append(f"漏洞扫描失败，异常信息: {str(e)}")
                task_status = "fail"

    if task_status == "success":
        with app.app_context():
            vuls = Vul.query.filter_by(task_id=task_id).first()
            if vuls:
                output.append("漏洞扫描结果已入库.")
            else:
                if os.path.exists(result_dir):
                    df = pandas.read_csv(
                        result_dir,
                        names=[
                            "rule_name",
                            "rule_description",
                            "threat_level",
                            "vulnerability_description",
                            "source_file",
                            "start_line",
                            "start_col",
                            "end_line",
                            "end_col",
                        ],
                        quotechar='"',
                    )
                    rule_name_translation = {
                        "Multiplication result converted to larger type": "类型转换漏洞",
                        "Time-of-check time-of-use filesystem race condition": "TOCTOU文件系统竞争条件漏洞",
                        "Uncontrolled data in SQL query": "SQL注入漏洞",
                    }
                    df["rule_name"] = (
                        df["rule_name"].map(
                            rule_name_translation).fillna(df["rule_name"])
                    )

                    rule_description_translation = {
                        "Including user-supplied data in a SQL query without neutralizing special elements can make code vulnerable to SQL Injection.": "在SQL查询中包含用户提供的数据而不消除特殊字符，可能使代码易受SQL注入攻击。",
                        "Separately checking the state of a file before operating on it may allow an attacker to modify the file between the two operations.": "在对文件操作之前单独检查其状态，可能会允许攻击者在这两个操作之间修改文件。",
                        "A multiplication result that is converted to a larger type can be a sign that the result can overflow the type converted from.": "将乘法结果转换为更大类型可能表明结果有可能溢出原类型。",
                    }
                    df["rule_description"] = (
                        df["rule_description"]
                        .map(rule_description_translation)
                        .fillna(df["rule_description"])
                    )

                    threat_level_translation = {
                        "error": "错误",
                        "warning": "警告",
                    }
                    df["threat_level"] = (
                        df["threat_level"]
                        .map(threat_level_translation)
                        .fillna(df["threat_level"])
                    )

                    for rule_name, group in df.groupby("rule_name"):
                        for item in group.iterrows():
                            rule = Rule.query.filter_by(
                                rule_name=rule_name).first()
                            if not rule:
                                new_rule = Rule(
                                    rule_name=rule_name,
                                    rule_description=item[1]["rule_description"],
                                    threat_level=item[1]["threat_level"],
                                )
                                db.session.add(new_rule)
                                db.session.commit()
                                rule = Rule.query.filter_by(
                                    rule_name=rule_name).first()

                            new_vul = Vul(
                                task_id=task_id,
                                rule_id=rule.id,
                                vulnerability_description=item[1][
                                    "vulnerability_description"
                                ],
                                source_file=item[1]["source_file"],
                                start_line=item[1]["start_line"],
                                start_col=item[1]["start_col"],
                                end_line=item[1]["end_line"],
                                end_col=item[1]["end_col"],
                                poc="",
                                vulReport="",
                                vulPatch="",
                            )
                            db.session.add(new_vul)
                            db.session.commit()
    if task_status == "success":
        task_status = "finished"


@app.route("/get_output")
def get_output():

    def generate():
        global output
        global task_status
        while task_status == "success" or task_status == "fail" or task_status == "finished":
            for line in output:
                yield f"data: {line}\n\n"
            output = []
            if task_status == "finished":
                yield "data: 漏洞扫描任务完成.\n\n"
                break

    return Response(generate(), content_type="text/event-stream")


def get_function_by_linenumber(
    database_path, file_path, start_line_number, end_line_number
):
    query = f"""
import cpp

private predicate hasBody(Function f) {{ exists(Stmt s | s.getEnclosingFunction() = f) }}

private int maxEndLineOfBody(Function f) {{
  result = max(Stmt s | s.getEnclosingFunction() = f | s.getLocation().getEndLine())
}}

private int getRealEndLine(Function f) {{
  result = maxEndLineOfBody(f) and hasBody(f)
  or
  result = f.getLocation().getEndLine() and not hasBody(f)
}}

from Function f, File file
where file.getAbsolutePath() = "{file_path}" 
and f.getLocation().getStartLine() <= {start_line_number} 
and getRealEndLine(f) >= {end_line_number}
select f.getName(), f.getAFile().getAbsolutePath(), f.getLocation().getStartLine(), getRealEndLine(f)
    """

    print(query)

    query_file = configs["ql_path"] + "getFunctionByLinenumber.ql"
    # print(query_file)
    with open(query_file, "w", encoding="utf-8") as f:
        f.write(query)

    command = [
        configs["codeql_path"],
        "query",
        "run",
        query_file,
        "--database",
        database_path,
        "--output",
        configs["data_dir"] + "result.bqrs",
    ]

    # print(command)

    try:
        subprocess.run(command, check=True, capture_output=True, text=True)

        # Decode result using CodeQL CLI
        decode_command = [
            configs["codeql_path"],
            "bqrs",
            "decode",
            configs["data_dir"] + "result.bqrs",
            "--format",
            "json",
        ]
        result = subprocess.run(
            decode_command, check=True, capture_output=True, text=True
        )

        output_json = json.loads(result.stdout)
        return output_json
    except subprocess.CalledProcessError as e:
        print("Error running CodeQL query:", e.stderr)
        return None


def get_macroinvocation_by_argument(database_path, argument_name):
    query = f"""
import cpp

from MacroInvocation mi
where exists(int i | mi.getExpandedArgument(i).toString() = "{argument_name}")
select mi.getMacroName(), mi.getFile().getAbsolutePath(), mi.getLocation().getStartLine(),
  mi.getLocation().getEndLine()
    """

    # print(query)

    query_file = configs["ql_path"] + "getMacroInvocationByArgument.ql"

    with open(query_file, "w", encoding="utf-8") as f:
        f.write(query)

    command = [
        configs["codeql_path"],
        "query",
        "run",
        query_file,
        "--database",
        database_path,
        "--output",
        configs["data_dir"] + "result.bqrs",
    ]

    # print(command)

    try:
        subprocess.run(command, check=True, capture_output=True, text=True)

        # Decode result using CodeQL CLI
        decode_command = [
            configs["codeql_path"],
            "bqrs",
            "decode",
            configs["data_dir"] + "result.bqrs",
            "--format",
            "json",
        ]
        result = subprocess.run(
            decode_command, check=True, capture_output=True, text=True
        )

        output_json = json.loads(result.stdout)
        return output_json
    except subprocess.CalledProcessError as e:
        print("Error running CodeQL query:", e.stderr)
        return None


def get_parents_by_functionname(database_path, function_name):
    query = f"""
import cpp

private predicate hasBody(Function f) {{ exists(Stmt s | s.getEnclosingFunction() = f) }}

private int maxEndLineOfBody(Function f) {{
  result = max(Stmt s | s.getEnclosingFunction() = f | s.getLocation().getEndLine())
}}

private int getRealEndLine(Function f) {{
  result = maxEndLineOfBody(f) and hasBody(f)
  or
  result = f.getLocation().getEndLine() and not hasBody(f)
}}

from Function f, Function g
where
  f.getName() = "{function_name}" and
  g = f.getACallToThisFunction().getEnclosingFunction()
select g.getName(), g.getAFile().getAbsolutePath(), g.getLocation().getStartLine(), getRealEndLine(g)
    """

    # print(query)

    query_file = configs["ql_path"] + "getParentByFunctionname.ql"

    with open(query_file, "w", encoding="utf-8") as f:
        f.write(query)

    command = [
        configs["codeql_path"],
        "query",
        "run",
        query_file,
        "--database",
        database_path,
        "--output",
        configs["data_dir"] + "result.bqrs",
    ]

    # print(command)

    try:
        subprocess.run(command, check=True, capture_output=True, text=True)

        # Decode result using CodeQL CLI
        decode_command = [
            configs["codeql_path"],
            "bqrs",
            "decode",
            configs["data_dir"] + "result.bqrs",
            "--format",
            "json",
        ]
        result = subprocess.run(
            decode_command, check=True, capture_output=True, text=True
        )

        output_json = json.loads(result.stdout)
        return output_json
    except subprocess.CalledProcessError as e:
        print("Error running CodeQL query:", e.stderr)
        return None


@app.route("/sourceVulAnalyze/<int:id>", methods=["GET"])
def sourceVulAnalyze(id):
    global conversation_history
    conversation_history = []

    vul = Vul.query.get_or_404(id)
    task = Task.query.get_or_404(vul.task_id)
    rule = Rule.query.get_or_404(vul.rule_id)
    bug = {}
    bug["id"] = vul.id
    bug["vulnerability_description"] = vul.vulnerability_description
    bug["source_file"] = vul.source_file
    db_dir = configs["data_dir"] + "db/" + task.name
    source_file = task.target + vul.source_file
    results = get_function_by_linenumber(
        db_dir, source_file, vul.start_line, vul.end_line
    )

    function = "\n"
    vul_lines = ""
    if results:
        print(results["#select"]["tuples"])
        with open(source_file, "r") as file:
            lines = file.readlines()
            for line in lines[
                results["#select"]["tuples"][0][2]
                - 1: results["#select"]["tuples"][0][3]
            ]:
                function += line
            function += "\n"
            for line in lines[int(vul.start_line) - 1: int(vul.end_line)]:
                vul_lines += line

        ancestor_index = 0
        parents = get_parents_by_functionname(
            db_dir, results["#select"]["tuples"][0][0])["#select"]["tuples"]
        ancestors = []
        for parent in parents:
            if parent not in ancestors:
                ancestors.append(parent)
        print(ancestors)
        while ancestor_index <= configs["max_caller"] and ancestor_index < len(ancestors):
            print(ancestor_index)
            print(ancestors[ancestor_index])
            with open(ancestors[ancestor_index][1], "r") as file1:
                lines = file1.readlines()
                for line in lines[ancestors[ancestor_index][2] - 1: ancestors[ancestor_index][3]]:
                    function += line
                function += "\n"
            macroInvocations = get_macroinvocation_by_argument(
                db_dir, ancestors[ancestor_index][0])
            if macroInvocations:
                print(macroInvocations["#select"]["tuples"])
                for macroInvocation in macroInvocations["#select"]["tuples"]:
                    with open(macroInvocation[1]) as file2:
                        lines = file2.readlines()
                        for line in lines[macroInvocation[2] - 1: macroInvocation[3]]:
                            function += line
                        function += "\n"
            parents = get_parents_by_functionname(
                db_dir, ancestors[ancestor_index][0])["#select"]["tuples"]
            for parent in parents:
                if parent not in ancestors:
                    ancestors.append(parent)
            ancestor_index += 1


    prompt1 = f"""
代码{vul_lines}中存在\"{vul.vulnerability_description}\"漏洞.
请你根据以下漏洞所在函数及其调用函数代码，先分析如何通过构造一个输入文件(名为{task.input})来触发该漏洞，然后编写一段python代码来生成该输入文件. 
{function}
"""

    return render_template("source/source_vul.html", bug=bug, task=task, prompt=prompt1)


def run_python_file(file_path):
    try:
        result = subprocess.run(
            ["python3", file_path], cwd=configs["data_dir"], capture_output=True, text=True, check=True
        )
        return True, result.stdout
    except subprocess.CalledProcessError as e:
        return False, e.stderr


def run_poc(runCommand, input):
    with open(input, "r") as file:
        input = file.read()

    try:
        result = subprocess.run(
            runCommand,
            input=input,
            capture_output=True,
            text=True,
            check=True,
        )
        return True, result.stdout
    except subprocess.CalledProcessError as e:
        return False, e.stderr


@app.route("/chat_with_llm", methods=["POST"])
def chatWithLLM():
    global conversation_history

    prompt = request.form.get("prompt")
    task_id = request.form.get("task_id")
    # print(task_id)
    task = Task.query.get_or_404(task_id)
    # print(task)

    client = AzureOpenAI(
        api_key=configs["gpt_4o_key"],
        api_version="2024-02-01",
        azure_endpoint=configs["gpt_4o_url"],
    )

    try:

        print(len(conversation_history))
        if len(conversation_history) > 4:
            conversation_history.pop(2)
            conversation_history.pop(2)

        conversation_history.append({"role": "user", "content": prompt})

        response = client.chat.completions.create(
            model="gpt-4o",
            messages=conversation_history,
        )

        assistant_reply = response.choices[0].message.content.strip()

        conversation_history.append(
            {"role": "assistant", "content": assistant_reply})

    except Exception as e:
        print(f"请求错误：{str(e)}")
        return f"请求错误：{str(e)}"

    # print(responseText)

    code_blocks = re.findall(r"```python\n(.*?)```",
                             assistant_reply, re.DOTALL)
    # print(code_blocks)
    if code_blocks:
        with open(configs["data_dir"]+"test.py", "w") as file:
            file.write(code_blocks[0])

        success, output = run_python_file(configs["data_dir"]+"test.py")

        if success:
            success1, output1 = run_poc(
                task.target + "/" +
                task.runCommand, configs["data_dir"] + task.input
            )
            if success1:
                prompt2 = f"运行你生成的输入文件的结果是: 运行正常，未触发漏洞."
            else:
                prompt2 = f"运行你生成的输入文件的结果是: {output1}"
        else:
            prompt2 = f"运行你生成的python代码的结果是: {output}"
    else:
        prompt2 = f"请你根据以下漏洞所在函数及其调用函数代码，先分析如何通过构造一个输入文件来触发该漏洞，然后编写一段python代码来生成该输入文件. "

    timeToStop = "yes"

    return jsonify(
        {"response": assistant_reply, "nextPrompt": prompt2, "timeToStop": timeToStop}
    )


@app.route("/save_poc", methods=["POST"])
def savePoC():
    vul_id = request.form.get("vul_id")
    print(vul_id)
    vul = Vul.query.get_or_404(vul_id)
    task = Task.query.get_or_404(vul.task_id)
    file_extension = str(configs["data_dir"] + task.input).split('.')[1]

    try:
        shutil.copy(configs["data_dir"] + task.input, configs["data_dir"] +
                    "poc/"+vul_id + "." + file_extension)
        shutil.copy(configs["data_dir"]+"test.py",
                    configs["data_dir"]+"poc/"+vul_id+"_python.py")
        vul.poc = str(vul.id)+"." + file_extension
        db.session.commit()
        return jsonify("已保存")
    except FileNotFoundError as err:
        return jsonify("保存失败")

# =============================================================================================


if __name__ == "__main__":
    app.run(debug=True)
