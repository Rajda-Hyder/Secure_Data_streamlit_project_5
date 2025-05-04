# imports
import streamlit as st

# function to initialize default value and avoiding errors
def get_session_state():
    if "logged_in" not in st.session_state:
        st.session_state.logged_in = False
        st.session_state.username = ""
        st.session_state.failed_attempts = 0
    return st.session_state

# function to True logged in attempts of user
def login_user(username: str):
    st.session_state.logged_in = True
    st.session_state.username = username
    st.session_state.failed_attempts = 0

# function to False logged in attempts of user
def logout_user():
    st.session_state.logged_in = False
    st.session_state.username = ""
    st.session_state.failed_attempts = 0

# function to increment fail attempts
def increment_failed_attempts():
    st.session_state.failed_attempts += 1

# function to reset fail attempts
def reset_failed_attempts():
    st.session_state.failed_attempts = 0
