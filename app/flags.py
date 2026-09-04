"""Flag access - the ONLY place flags enter the app.

Design rules (brief requirement #5 "Izolacia flagov"):
  * Flags are read from environment variables, never hardcoded.
  * Flags are NOT stored in the database. No SQLi/UNION can return one.
      Exception: W1-02 injects its single flag into the DB at seed time,
      because that task requires the flag to BE the leaked data.
  * A flag is emitted by application logic only AFTER the task condition is
      met - never dumped from storage.
  * Env-var name = FLAG_ + the task id with '-' replaced by '_', upper-cased.
      Task W1-05  ->  FLAG_W1_05
    (Hyphens are avoided in env names so shells / .env files stay portable.)
"""
import os


def env_name(task_id: str) -> str:
    return "FLAG_" + task_id.replace("-", "_").upper()


def get_flag(task_id: str) -> str:
    return os.environ.get(env_name(task_id), "FLAG_" + task_id + "_NOT_SET")
