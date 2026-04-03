"""
================================================================================
PROJECT: Big’s BBQ File Search Chatbot (Prometheus)
MODULE: Dual KB Ingestion Script
AUTHOR: Jermaine Hunter (HunterCloudSec)
--------------------------------------------------------------------------------
PURPOSE:
Create two separate vector stores:
1. Public KB  -> for menu, jobs, public policy
2. Private KB -> for recipes, manager notes, internal docs

EXPECTED STRUCTURE:
../kb_pdfs/
    public/
        jobs.pdf
        menu.pdf
        public-policy.pdf
    private/
        manager-notes.pdf
        super-secret-sauce.pdf

OUTPUT:
Prints PUBLIC_VECTOR_STORE_ID and PRIVATE_VECTOR_STORE_ID for use in .env
================================================================================
"""

import os
from openai import OpenAI
from dotenv import load_dotenv

load_dotenv()

api_key = os.getenv("OPENAI_API_KEY")
if not api_key:
    raise ValueError("OPENAI_API_KEY is missing from .env")

client = OpenAI(api_key=api_key)

PUBLIC_DIR = "../kb_pdfs/public"
PRIVATE_DIR = "../kb_pdfs/private"


def get_pdf_files(directory: str) -> list[str]:
    """Return a list of PDF file paths from a directory."""
    if not os.path.exists(directory):
        print(f"ERROR: Could not find directory at {os.path.abspath(directory)}")
        return []

    return [
        os.path.join(directory, f)
        for f in os.listdir(directory)
        if f.lower().endswith(".pdf")
    ]


def create_and_fill_vector_store(store_name: str, pdf_files: list[str]) -> str:
    """Create a vector store and upload all provided PDFs."""
    if not pdf_files:
        raise ValueError(f"No PDF files found for store: {store_name}")

    print(f"\nCreating vector store: {store_name}")
    vector_store = client.vector_stores.create(name=store_name)
    print(f"{store_name} ID = {vector_store.id}")

    for file_path in pdf_files:
        with open(file_path, "rb") as f:
            client.vector_stores.files.upload_and_poll(
                vector_store_id=vector_store.id,
                file=f
            )
        print(f"Uploaded to {store_name}: {os.path.basename(file_path)}")

    return vector_store.id


def main():
    public_files = get_pdf_files(PUBLIC_DIR)
    private_files = get_pdf_files(PRIVATE_DIR)

    print("Found PUBLIC PDF files:")
    for f in public_files:
        print("-", f)

    print("\nFound PRIVATE PDF files:")
    for f in private_files:
        print("-", f)

    public_store_id = create_and_fill_vector_store(
        "Bigs BBQ Public Knowledge Base",
        public_files
    )

    private_store_id = create_and_fill_vector_store(
        "Bigs BBQ Private Knowledge Base",
        private_files
    )

    print("\nDone.")
    print("Copy these into .env:\n")
    print(f"PUBLIC_VECTOR_STORE_ID={public_store_id}")
    print(f"PRIVATE_VECTOR_STORE_ID={private_store_id}")


if __name__ == "__main__":
    main()