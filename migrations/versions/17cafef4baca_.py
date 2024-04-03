"""empty message

Revision ID: 17cafef4baca
Revises: 5d31012871f4
Create Date: 2024-04-03 20:05:53.038437

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '17cafef4baca'
down_revision = '5d31012871f4'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.add_column(sa.Column('profile_picture', sa.String(length=100), nullable=True))
        batch_op.add_column(sa.Column('bio', sa.Text(), nullable=True))
        batch_op.add_column(sa.Column('twitter_username', sa.String(length=50), nullable=True))
        batch_op.add_column(sa.Column('facebook_username', sa.String(length=50), nullable=True))

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.drop_column('facebook_username')
        batch_op.drop_column('twitter_username')
        batch_op.drop_column('bio')
        batch_op.drop_column('profile_picture')

    # ### end Alembic commands ###
