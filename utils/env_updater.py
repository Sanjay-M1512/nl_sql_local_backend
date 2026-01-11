from dotenv import dotenv_values

ENV_PATH = ".env"

def update_env_variable(key, value):
    # Read existing .env
    env_vars = dotenv_values(ENV_PATH)

    # Update key
    env_vars[key] = value

    # Write back to .env
    with open(ENV_PATH, "w") as f:
        for k, v in env_vars.items():
            f.write(f"{k}={v}\n")
