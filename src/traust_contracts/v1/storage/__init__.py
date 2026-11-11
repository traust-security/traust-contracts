"""SQL-first db/v1/traust: the one-owner data model (XWING-2363).

The DDL is the contract (db/v1/traust); consumers load it through
bootstrap_files()/bootstrap_statements(). The write protocol (Store) is
rebuilt against this model once the DDL has landed.
"""
