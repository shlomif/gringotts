package MyManageNews;

use base 'Exporter';

our @EXPORT=(qw(get_news_manager));

use strict;
use warnings;

use HTML::Latemp::News;

my @news_items =
(
    (map 
        { 
            +{%$_, 
                'author' => "John Smith", 
                'category' => "My Site Category", 
            }
        }
        (
            # TODO: Fill Items Here.
        ),
    )
);

sub gen_news_manager
{
    return
        HTML::Latemp::News->new(
            'news_items' => \@news_items,
            'title' => "My Site News",
            'link' => "http://www.link-to-my-site.tld/",
            'language' => "en-US",
            'copyright' => "Copyright by John Smith, (c) 2005",
            'webmaster' => "John Smith <author\@domain.org>",
            'managing_editor' => "John Smith <author\@domain.org>",
            'description' => "News of the My Site",
        );
}

# A singleton.
{
    my $news_manager;

    sub get_news_manager
    {
        if (!defined($news_manager))
        {
            $news_manager = gen_news_manager();
        }
        return $news_manager;
    }
}

1;
