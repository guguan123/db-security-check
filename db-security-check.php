<?php
/*
Plugin Name: MySQL Security Monitor
Plugin URI: https://github.com/guguan123/db-security-check
Description: 监控数据库是否有异常
Version: 1.1
Author: A cat
Author URI: https://gemini.google.com
License: MIT
License URI: https://github.com/guguan123/db-security-check/blob/main/LICENSE
Text Domain: db-security-check
Requires at least: 6.0
Tested up to: 6.8
PHP Version: 8.2
Requires PHP: 7.0
*/

if (!defined('ABSPATH')) exit;

class GG_DB_Security_Monitor {

	const OPTION_NAME = 'gg_db_monitor_settings';
	const RESULT_OPTION_NAME = 'gg_db_monitor_result';

	/** @var self 静态实例变量 */
	private static $instance = null;

	// 静态初始化入口
	public static function init() {
		if (null === self::$instance) {
			self::$instance = new self();

			// 核心生命周期钩子
			register_activation_hook(__FILE__, array(self::$instance, 'activate'));
			register_deactivation_hook(__FILE__, array(self::$instance, 'deactivate'));

			// 卸载钩子
			register_uninstall_hook(__FILE__, array(__CLASS__, 'uninstall'));
		}
		return self::$instance;
	}

	// 构造函数设为私有或普通，但在 init 中调用
	private function __construct() {
		add_action('admin_menu', array($this, 'create_menu'));
		add_action('gg_db_weekly_check_event', array($this, 'run_security_check_cron'));
		add_action('admin_notices', array($this, 'display_admin_alerts'));
	}

	private function run_security_check() {
		global $wpdb;
		$alerts = [];
		$settings = get_option(self::OPTION_NAME);

		// 检测 --skip-grant-tables
		$result = $wpdb->get_row("SHOW VARIABLES LIKE 'skip_grant_tables'");
		if ($result && isset($result->Value) && strtoupper($result->Value) == 'ON') {
			$alerts[] = "🚨 危险：数据库正处于 --skip-grant-tables 模式运行！";
		}

		// 获取白名单逻辑：如果没设置过，就用默认的
		$allowed_db = (isset($settings['allowed_databases']) && is_array($settings['allowed_databases'])) 
					  ? $settings['allowed_databases'] 
					  : array($wpdb->dbname, 'information_schema', 'performance_schema', 'mysql', 'sys');

		// 检测异常数据库
		$unknown_dbs = array_diff($wpdb->get_col("SHOW DATABASES"), $allowed_db);

		if (!empty($unknown_dbs)) $alerts[] = "🔍 检测到异常数据库：" . implode(', ', $unknown_dbs);

		return $alerts;
	}

	public function run_security_check_cron() {
		$alerts = $this->run_security_check();
		if (!empty($alerts)) {
			$settings = get_option(self::OPTION_NAME);
			if (!empty($settings['email_notify'])) {
				$to = get_option('admin_email');
				$subject = '[' . get_bloginfo('name') . '] 数据库异常警报喵！';
				$body = implode(PHP_EOL, $alerts);
				wp_mail($to, $subject, $body);
			}
		}
		update_option(self::RESULT_OPTION_NAME, array('time' => current_time('Y-m-d H:i:s'), 'result' => $alerts));
	}

	// 创建管理页面
	public function create_menu() {
		add_options_page('DB Security', 'DB Security', 'manage_options', 'gg-db-monitor', array($this, 'settings_page'));
	}

	public function settings_page() {
		global $wpdb;
		
		if (isset($_POST['submit'])) {
			if (!current_user_can('manage_options')) wp_die(__('您没有权限操作此页面喵！'));
			// 校验 Nonce
			check_admin_referer('gg_db_save_action');
			// 将逗号或换行分隔的字符串转为数组
			$db_input = str_replace(array("\r", "\n"), ',', $_POST['allowed_databases']);
			$db_array = array_filter(array_map('trim', explode(',', $db_input)));
			
			$new_settings = array(
				'email_notify' => isset($_POST['email_notify']) ? 1 : 0,
				'allowed_databases' => array_values(array_unique($db_array))
			);
			update_option(self::OPTION_NAME, $new_settings);
			echo '<div class="updated notice is-dismissible"><p>设置已保存喵！</p></div>';
			$settings = $new_settings;
		} else {
			$settings = get_option(self::OPTION_NAME);
		}

		// 每次打开页面都自动运行检测
		$alerts = $this->run_security_check();
		$current_db_list = implode("\n", $settings['allowed_databases'] ?? []);

		?>
		<div class="wrap">
			<h1>MySQL Security Monitor</h1>
			<p>当前数据库：<code><?php echo esc_html($wpdb->dbname); ?></code></p>
			<hr>
			<h3>当前状态：</h3>
			<?php if (empty($alerts)): ?>
				<div class="notice notice-success inline"><p><strong>✅ 一切正常喵~</strong></p></div>
			<?php else: ?>
				<div class="notice notice-error inline">
					<p><strong>⚠️ 发现隐患：</strong></p>
					<ul><?php foreach ($alerts as $alert) echo "<li>".esc_html($alert)."</li>"; ?></ul>
				</div>
			<?php endif; ?>

			<form method="post" style="margin-top: 20px; background: #fff; padding: 20px; border: 1px solid #ccd0d4; border-radius: 5px;">
				<?php wp_nonce_field('gg_db_save_action'); ?>
				<h3>设置</h3>
				<table class="form-table">
					<tr>
						<th scope="row">邮件通知</th>
						<td><input type="checkbox" name="email_notify" <?php checked(1, $settings['email_notify'] ?? 0); ?>> 开启</td>
					</tr>
					<tr>
						<th scope="row">数据库白名单</th>
						<td>
							<textarea name="allowed_databases" rows="6" class="large-text code" placeholder="每行一个数据库名称"><?php echo esc_textarea($current_db_list); ?></textarea>
						</td>
					</tr>
				</table>
				<?php submit_button('保存设置'); ?>
			</form>
		</div>
		<?php
	}

	// 后台顶部提醒
	public function display_admin_alerts() {
		// 只在非此插件设置页面显示提醒
		if (isset($_GET['page']) && $_GET['page'] === 'gg-db-monitor') return;
		if (!current_user_can('manage_options')) return;

		// 获取检测报告
		$check_result = get_option(self::RESULT_OPTION_NAME);
		if (!empty($check_result['result'])) {
			?>
			<div class="notice notice-error is-dismissible">
				<p><strong>🚨 数据库警告！</strong> 发现异常，请 <a href="<?php echo admin_url('options-general.php?page=gg-db-monitor'); ?>">查看详情</a> 喵！</p>
			</div>
			<?php
		}
	}

	public function activate() {
		global $wpdb;

		// 初始化白名单
		if (!get_option(self::OPTION_NAME)) {
			update_option(self::OPTION_NAME, array(
				'email_notify' => 1,
				'allowed_databases' => array($wpdb->dbname, 'information_schema', 'performance_schema', 'mysql', 'sys')
			));
		}
		if (!wp_next_scheduled('gg_db_weekly_check_event')) {
			wp_schedule_event(time(), 'weekly', 'gg_db_weekly_check_event');
		}
	}

	public function deactivate() {
		wp_clear_scheduled_hook('gg_db_weekly_check_event');
	}

	public static function uninstall() {
		delete_option(self::OPTION_NAME);
		delete_option(self::RESULT_OPTION_NAME);
	}
}

// 启动插件
GG_DB_Security_Monitor::init();