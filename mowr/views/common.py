import datetime

import dateutil.parser

from mowr import db
from mowr.models.sample import Sample
from mowr.models.tag import Tag
from mowr.models.tag import get_tags_table

PER_PAGE = 20


def search(query='', page=1):  # TODO factorize/simplify
    """ Search for a sample matching query
     :param int page: The page to show
     :param str query: The search query as `field:value field2:value2 field3:value3...`
    """
    if ':' in query:
        filters = query.split()
        sql_params = []
        subq, subq2, tags = None, None, None
        for f in filters:
            if ':' not in f:  # Maybe there was a space but no ':' next to it ?
                continue
            f = f.split(':')
            if f[0] not in ['name', 'md5', 'sha1', 'sha256', 'first_analysis', 'last_analysis', 'tags']:
                continue
            field, value = f[0], f[1]

            if field in ['first_analysis', 'last_analysis']:
                try:
                    date = dateutil.parser.parse(value)
                except ValueError:
                    continue
                sql_params.append(getattr(Sample, field) >= date)
                date += datetime.timedelta(days=1)
                sql_params.append(getattr(Sample, field) < date)
            elif field == 'name':
                subq = db.session.query(Sample.sha256, db.func.unnest(Sample.name).label('name')).subquery()
                subq2 = db.session.query(subq.c.sha256.distinct().label('sha256')).filter(
                    subq.c.name.like('%{name}%'.format(name=value))).subquery()
            elif field == 'tags':
                tags = get_tags_table()
                sql_params.append(Tag.name.like('%{tag}%'.format(tag=value)))
            else:
                sql_params.append(getattr(Sample, field).like('%{val}%'.format(val=value)))

        # Execute the query
        if subq2 is not None and tags is not None:
            samples = Sample.query.filter(*sql_params).join(subq2, Sample.sha256 == subq2.c.sha256).join(tags,
                                                                                                  tags.c.sample_sha256 == Sample.sha256).join(
                Tag, tags.c.tag_id == Tag.id).paginate(page, PER_PAGE)
        elif tags is not None:
            samples = Sample.query.filter(*sql_params).join(tags,
                                                     tags.c.sample_sha256 == Sample.sha256).join(
                Tag, tags.c.tag_id == Tag.id).paginate(page, PER_PAGE)
        elif subq2 is not None:
            samples = Sample.query.filter(*sql_params).join(subq2, Sample.sha256 == subq2.c.sha256).paginate(page, PER_PAGE)
        else:
            samples = Sample.query.filter(*sql_params).paginate(page, PER_PAGE)
    else:
        samples = Sample.query.filter(Sample.sha256.like('%{sha256}%'.format(sha256=query))).paginate(page, PER_PAGE)
        if not samples.items:
            # Search name
            subq = db.session.query(Sample.sha256, db.func.unnest(Sample.name).label('name')).subquery()
            subq2 = db.session.query(subq.c.sha256.distinct().label('sha256')).filter(
                subq.c.name.like('%{val}%'.format(val=query))).subquery()
            samples = Sample.query.join(subq2, Sample.sha256 == subq2.c.sha256).paginate(page, PER_PAGE)
    return samples
