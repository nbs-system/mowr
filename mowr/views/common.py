import shlex
import dateutil.parser
import datetime

from mowr import db
from mowr.models.sample import Sample
from mowr.models.tag import Tag
from mowr.models.tag import get_tags_table

PER_PAGE = 20


def search(query='', page=1):  # TODO factorize/simplify
    """ Search for a sample matching query

     :param str query: The search query
     """
    if ':' in query:
        elems = [elem.replace(':', '') for elem in shlex.split(query)]
        if len(elems) % 2 == 1:
            elems.append('')

        req = []
        # Add every condition to the query
        subq, subq2 = None, None
        tags = None
        for i in range(0, len(elems), 2):
            prefix, value = elems[i:i+2]
            if prefix not in ['name', 'md5', 'sha1', 'sha256', 'first_analysis', 'last_analysis', 'tags']:
                continue
            elif prefix in ['first_analysis', 'last_analysis']:
                try:
                    date = dateutil.parser.parse(value)
                except ValueError:
                    continue
                req.append(getattr(Sample, prefix) >= date)
                date += datetime.timedelta(days=1)
                req.append(getattr(Sample, prefix) < date)
            elif prefix == 'name':
                subq = db.session.query(Sample.sha256, db.func.unnest(Sample.name).label('name')).subquery()
                subq2 = db.session.query(subq.c.sha256.distinct().label('sha256')).filter(
                    subq.c.name.like('%{name}%'.format(name=value))).subquery()
            elif prefix == 'tags':
                tags = get_tags_table()
                req.append(Tag.name.like('%{tag}%'.format(tag=value)))
                samples = Sample.query.filter() \
                    .join(tags,
                          tags.c.sample_sha256 == Sample.sha256) \
                    .join(Tag,
                          Tag.id == tags.c.tag_id) \
                    .all()
                print(samples)
            else:
                req.append(getattr(Sample, prefix).like('%{val}%'.format(val=value)))
        # Execute the query
        if subq2 is not None and tags is not None:
            samples = Sample.query.filter(*req).join(subq2, Sample.sha256 == subq2.c.sha256).join(tags,
                                                                                                  tags.c.sample_sha256 == Sample.sha256).join(
                Tag, tags.c.tag_id == Tag.id).paginate(page, PER_PAGE)
        elif tags is not None:
            samples = Sample.query.filter(*req).join(tags,
                                                     tags.c.sample_sha256 == Sample.sha256).join(
                Tag, tags.c.tag_id == Tag.id).paginate(page, PER_PAGE)
        elif subq2 is not None:
            samples = Sample.query.filter(*req).join(subq2, Sample.sha256 == subq2.c.sha256).paginate(page, PER_PAGE)
        else:
            samples = Sample.query.filter(*req).paginate(page, PER_PAGE)
    else:
        samples = Sample.query.filter(Sample.sha256.like('%{sha256}%'.format(sha256=query))).paginate(page, PER_PAGE)
        if not samples.items:
            # Search name
            subq = db.session.query(Sample.sha256, db.func.unnest(Sample.name).label('name')).subquery()
            subq2 = db.session.query(subq.c.sha256.distinct().label('sha256')).filter(
                subq.c.name.like('%{val}%'.format(val=query))).subquery()
            samples = Sample.query.join(subq2, Sample.sha256 == subq2.c.sha256).paginate(page, PER_PAGE)
    return samples
