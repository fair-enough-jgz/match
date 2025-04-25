from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    vuls = db.relationship("Vul", backref=db.backref("task", lazy=True))
    type = db.Column(db.String(120), unique=False, nullable=False)
    name = db.Column(db.String(120), unique=False, nullable=False)
    target = db.Column(db.String(120), unique=False, nullable=False)
    compileCommand = db.Column(db.String(120), unique=False, nullable=True)
    runCommand = db.Column(db.String(120), unique=False, nullable=True)
    input = db.Column(db.String(120), unique=False, nullable=True)
    createTime = db.Column(db.String(120), unique=False, nullable=False)

    def __repr__(self):
        return f"Task('{self.name}', '{self.target}', '{self.compileCommand}','{self.runCommand}','{self.input}', '{self.createTime}')"


# class BinaryTask(db.Model):
#     id = db.Column(db.Integer, primary_key=True)
#     type = db.Column(db.String(120), unique=False, nullable=False)
#     name = db.Column(db.String(120), unique=False, nullable=False)
#     target = db.Column(db.String(120), unique=False, nullable=False)
#     compileCommand = db.Column(db.String(120), unique=False, nullable=True)
#     createTime = db.Column(db.String(120), unique=False, nullable=False)
#
#     def __repr__(self):
#         return f"BinaryTask('{self.name}', '{self.target}', '{self.compileCommand}', '{self.createTime}')"
#

class Rule(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    rule_name = db.Column(db.String(120), unique=False, nullable=False)
    rule_description = db.Column(db.String(120), unique=False, nullable=False)
    threat_level = db.Column(db.String(120), unique=False, nullable=False)

    def __repr__(self):
        return (
            f"Vul('{self.rule_name}', '{self.rule_description}', '{self.threat_level}')"
        )


class Vul(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    task_id = db.Column(db.Integer, db.ForeignKey("task.id"), nullable=False)
    rule_id = db.Column(db.Integer, db.ForeignKey("rule.id"), nullable=False)
    vulnerability_description = db.Column(db.String(120), unique=False, nullable=False)
    source_file = db.Column(db.String(120), unique=False, nullable=False)
    start_line = db.Column(db.String(120), unique=False, nullable=False)
    start_col = db.Column(db.String(120), unique=False, nullable=False)
    end_line = db.Column(db.String(120), unique=False, nullable=False)
    end_col = db.Column(db.String(120), unique=False, nullable=False)
    poc = db.Column(db.String(120), unique=False, nullable=True)
    vulReport = db.Column(db.String(120), unique=False, nullable=True)
    vulPatch = db.Column(db.String(120), unique=False, nullable=True)

    def __repr__(self):
        return f"Vul('{self.task_id}', '{self.rule_id}', '{self.vulnerability_description}', '{self.source_file}', '{self.start_line}', '{self.start_col}, '{self.end_line}', '{self.end_col}', '{self.poc}', '{self.vulReport}', '{self.vulPatch}')"
